"""Flask Blueprint ``authkit_sso`` registration and global lifecycle hooks.

This module exposes two public entry points:

- :func:`create_sso_blueprint` — creates the HTTP Blueprint for the SSO endpoint.
- :func:`init_app` — to pass to ``FLASK_APP_MUTATOR``; registers the global hooks
  for tenant context propagation and cleanup across the entire application.

Usage in ``superset_config.py``:

    from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
    BLUEPRINTS = [create_sso_blueprint()]
    FLASK_APP_MUTATOR = init_app

Hook architecture (ADR-003):

    before_request (global):
        For each request from a user authenticated via SAK (presence of
        ``session["_sak_tenant"]``), rehydrates the ContextVar and stores the
        restoration token in ``flask.g._sak_tenant_token``.

    teardown_request (global):
        Restores the ContextVar via ``reset(token)`` — or forces ``clear()``
        if the before_request hook was not executed — ensuring that no residual
        value can contaminate the next request on the same thread.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from flask import Blueprint

if TYPE_CHECKING:
    from flask import Flask

logger = logging.getLogger(__name__)

# Separate audit logger from application logs (ADR-003 §2.5).
# Configure in Python logging to route to a SIEM or a dedicated file.
_audit_logger = logging.getLogger("superset_auth_kit.security.audit")

_BLUEPRINT_NAME = "authkit_sso"
_URL_PREFIX = "/api/v1/auth"


def create_sso_blueprint() -> Blueprint:
    """Create and configure the Flask Blueprint for the AuthKit SSO flow.

    Endpoints exposed:
    - ``POST /api/v1/auth/sso`` — Exchanges a JWT token for a Superset session cookie.

    Hooks attached to the Blueprint (Blueprint scope only):
    - ``after_request``: Defensive HTTP security headers.
    - ``teardown_request``: Blueprint safety net — ``TenantContext.clear()``
      if the global hooks have not yet been registered (usage without ``init_app``).

    Returns:
        :class:`flask.Blueprint` instance ready to be listed in ``BLUEPRINTS``.
    """
    from superset_auth_kit.api.views import sso_view
    from superset_auth_kit.security.session import SessionFactory
    from superset_auth_kit.tenant.context import TenantContext

    bp = Blueprint(_BLUEPRINT_NAME, __name__, url_prefix=_URL_PREFIX)

    bp.add_url_rule(
        "/sso",
        view_func=sso_view,
        methods=["POST"],
        endpoint="sso",
    )

    @bp.after_request
    def add_security_headers(response: Any) -> Any:
        """Apply defensive HTTP headers to every response from the Blueprint."""
        return SessionFactory.apply_secure_headers(response)

    @bp.teardown_request
    def blueprint_teardown_fallback(exc: BaseException | None) -> None:
        """Blueprint-scoped safety net for context cleanup.

        The global hook (registered by :func:`init_app`) handles cleanup via
        ``reset(token)``. This hook is a final safety net: if ``init_app`` was
        not called, or if the global hook itself raised an exception, ``clear()``
        forces the value back to None.

        Flask executes Blueprint teardown_request hooks BEFORE application-level
        ones (LIFO registration order). The full sequence is therefore:
            1. This hook (Blueprint) → clear() if no global token
            2. Global hook (App)     → reset(token) or clear()
        Both operations are idempotent — no conflict.
        """
        # Check whether the global hook has already placed a token in g.
        # If so, let the global hook perform the reset(token) — do not interfere.
        from flask import g
        if not getattr(g, "_sak_tenant_token", None):
            # No global token → reset impossible → clear() as safety net.
            TenantContext.clear()

    logger.info(
        "[AuthKit] Blueprint '%s' registered: POST %s/sso",
        _BLUEPRINT_NAME,
        _URL_PREFIX,
    )
    return bp


def _register_global_hooks(app: Flask) -> None:  # noqa: C901
    """Register global before_request and teardown_request hooks on *app*.

    These hooks execute for **all** routes of the Superset application,
    not only the SSO Blueprint routes. This ensures that the tenant context
    is available during dashboard requests, chart API requests, etc.

    Design ADR-303 — Source sovereignty:
        The ``tenant_id`` is read **exclusively** from ``flask.session["_sak_tenant"]``,
        an HMAC-signed server-side key. Never from ``request.args``, ``request.headers``,
        or any other client-controllable input.

    Design ADR-306 — Fail Closed:
        An invalid tenant (regex fail) causes an immediate ``abort(403)`` with a
        CRITICAL audit log. An SAK user without a tenant in session causes an
        ``abort(403)`` with an ERROR audit log. Non-SAK users (Superset admin,
        public endpoints) are simply ignored.

    Args:
        app: Flask instance to instrument.
    """
    from flask import abort, g, has_request_context, request, session

    from superset_auth_kit.exceptions import TenantResolutionError
    from superset_auth_kit.tenant.context import TenantContext

    # Lazy import to avoid a hard dependency on flask_login at module level.
    # flask_login is always available in the Superset environment.
    try:
        from flask_login import current_user as _current_user_proxy
    except ImportError:
        logger.warning(
            "[AuthKit] flask_login not available — global tenant hooks disabled."
        )
        return

    @app.before_request
    def hydrate_tenant_context() -> None:
        """Rehydrate the tenant context from the server session.

        Decision strategy (in evaluation order):

        1. Residual detected (ContextVar non-None before hydration) → WARNING audit + clear.
        2. Unauthenticated user → skip (public endpoints, SSO itself).
        3. No ``_sak_tenant`` in session → skip (Superset admin, non-SAK users).
        4. ``_sak_tenant`` present but invalid → CRITICAL audit + abort(403).
        5. ``_sak_tenant`` valid → set_tenant() + store token in ``g``.
        """
        # ── Residual detection ────────────────────────────────────────────────
        residual = TenantContext.get_tenant_or_none()
        if residual is not None:
            _audit_logger.warning(
                json.dumps({
                    "event": "TENANT_RESIDUAL_DETECTED",
                    "tenant_id": residual,
                    "path": request.path,
                    "remote_addr": request.remote_addr,
                    "message": (
                        "ContextVar non-empty at the start of before_request — "
                        "teardown_request of the previous request did not clean up. "
                        "Forcing to None."
                    ),
                })
            )
            TenantContext.clear()

        # ── Authentication filter ─────────────────────────────────────────────
        if not _current_user_proxy.is_authenticated:
            return

        # ── Read from signed server session ──────────────────────────────────
        tenant_id: str | None = session.get("_sak_tenant")

        if not tenant_id:
            # Authenticated user without SAK key → Superset admin or non-SSO
            # route. Do not interrupt: no tenant context required.
            return

        # ── Validation and hydration ──────────────────────────────────────────
        try:
            token = TenantContext.set_tenant(tenant_id)
        except TenantResolutionError as exc:
            # Invalid value in session (regex fail) — critical anomaly:
            # either the session was corrupted or a validation regression occurred.
            _audit_logger.critical(
                json.dumps({
                    "event": "TENANT_ID_INVALID",
                    "tenant_id_raw": tenant_id[:32] if tenant_id else None,
                    "sub": getattr(_current_user_proxy, "username", "?"),
                    "path": request.path,
                    "remote_addr": request.remote_addr,
                    "message": (
                        f"tenant_id in session failed regex validation: {exc}"
                    ),
                })
            )
            abort(403)

        # Store token in g for teardown (deterministic reset).
        g._sak_tenant_token = token

        _audit_logger.debug(
            json.dumps({
                "event": "TENANT_CONTEXT_HYDRATED",
                "tenant_id": tenant_id,
                "sub": getattr(_current_user_proxy, "username", "?"),
                "path": request.path,
            })
        )

    @app.teardown_request
    def cleanup_tenant_context(exc: BaseException | None) -> None:
        """Restore the ContextVar to its previous state after each request.

        Executed by Flask via ``RequestContext.pop()`` in a ``try/finally`` —
        guaranteed even if the view raised a Python or SQLAlchemy exception.

        Strategy:
        - If ``g._sak_tenant_token`` is present → ``reset(token)`` (deterministic
          restoration of the previous state, typically ``None``).
        - Otherwise → ``clear()`` as a safety net (before_request skipped
          hydration: unauthenticated user, non-SAK, etc.).

        Note on sequence with Blueprint teardown:
        In Flask, Blueprint teardowns execute BEFORE application-level ones
        (registration order). This hook executes LAST and guarantees the final
        state of the ContextVar for the next user of the thread.
        """
        if not has_request_context():
            return

        token = getattr(g, "_sak_tenant_token", None)
        if token is not None:
            # Clear the reference BEFORE reset() so that a second call
            # (preserve_context in test client, or double teardown) finds None
            # and falls into the else → idempotent clear().
            g._sak_tenant_token = None
            TenantContext.reset(token)
        else:
            TenantContext.clear()


def init_app(app: Flask) -> None:
    """AuthKit initialization hook — to pass to ``FLASK_APP_MUTATOR``.

    Performs two actions at Superset application startup:

    1. Validation of cookie security configuration.
    2. Registration of the global ``before_request`` / ``teardown_request`` hooks
       for tenant context propagation (ADR-003).

    Args:
        app: :class:`flask.Flask` instance provided by Superset at startup.
    """
    from superset_auth_kit.security.session import SessionFactory

    warnings = SessionFactory.validate_app_config(dict(app.config))
    if not warnings:
        logger.info("[AuthKit] Cookie configuration is compliant.")
    else:
        logger.warning(
            "[AuthKit] Initialization completed with %d configuration warning(s).",
            len(warnings),
        )

    _register_global_hooks(app)
    logger.info("[AuthKit] Global tenant context hooks registered on the application.")
