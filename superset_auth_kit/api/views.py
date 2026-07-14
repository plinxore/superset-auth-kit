"""Flask view for the ``POST /api/v1/auth/sso`` endpoint.

Nominal flow:
1. Validate the JSON payload via :class:`~superset_auth_kit.api.schemas.SsoRequestSchema`.
2. Retrieve the Superset SecurityManager from ``current_app.appbuilder.sm``.
3. Delegate to ``sm.authenticate_sso(raw_token)`` → FAB User object.
4. Session fixation: ``session.clear()`` + ``flask_login.login_user(fresh=True)``.
5. Final validation of ``redirect_to`` (defense in depth).
6. ``302 Redirect`` response to ``redirect_to``.

Strict logging rule:
- The raw token content is NEVER logged.
- The full email is NEVER logged — only the first 8 characters of ``sub``.
- Token errors only log the exception type, not the message.
"""

from __future__ import annotations

import logging
from typing import Any

import flask_login
from flask import current_app, jsonify, redirect, request, session
from marshmallow import ValidationError

from superset_auth_kit.api.schemas import SsoRequestSchema, validate_redirect_path
from superset_auth_kit.exceptions import (
    AuthKitError,
    TokenExpiredError,
    TokenInvalidError,
    TokenReplayError,
)
from superset_auth_kit.tenant.context import TenantContext

logger = logging.getLogger(__name__)

_schema = SsoRequestSchema()


def sso_view() -> Any:
    """Handler for the ``POST /api/v1/auth/sso`` endpoint.

    Return codes:
    - ``302``: Authentication successful, redirect to ``redirect_to``.
    - ``400``: Invalid payload, expired token, invalid ``redirect_to``,
               or non-signature AuthKit error.
    - ``401``: Invalid token (signature, claims).
    - ``500``: Server configuration error (SecurityManager misconfigured).
    """
    # ── 1. Payload parsing and validation ────────────────────────────────────
    json_data = request.get_json(silent=True)
    if json_data is None:
        logger.warning(
            "[AuthKit] SSO request rejected: non-JSON Content-Type or empty body. "
            "remote_addr=%s",
            request.remote_addr,
        )
        return jsonify({"error": "JSON payload required (Content-Type: application/json)."}), 400

    try:
        data: dict[str, Any] = _schema.load(json_data)
    except ValidationError as exc:
        logger.warning(
            "[AuthKit] SSO request rejected: payload validation failed. "
            "fields=%s remote_addr=%s",
            list(exc.messages.keys()),
            request.remote_addr,
        )
        return jsonify({"error": "Invalid payload.", "details": exc.messages}), 400

    raw_token: str = data["token"]
    redirect_to: str = data["redirect_to"]

    # ── 2. SecurityManager retrieval ─────────────────────────────────────────
    try:
        sm = _get_security_manager()
    except RuntimeError as exc:
        logger.error("[AuthKit] Unable to retrieve SecurityManager: %s", exc)
        return jsonify({"error": "Invalid server configuration."}), 500

    if not hasattr(sm, "authenticate_sso"):
        logger.error(
            "[AuthKit] CUSTOM_SECURITY_MANAGER does not have authenticate_sso. "
            "Use build_manager() in superset_config.py."
        )
        return jsonify({"error": "Invalid server configuration."}), 500

    # ── 3. SSO authentication ─────────────────────────────────────────────────
    logger.info("[AuthKit] Token validation started. remote_addr=%s", request.remote_addr)

    try:
        user = sm.authenticate_sso(raw_token)
    except TokenExpiredError:
        # Expired token: expected error, no stack trace.
        logger.info(
            "[AuthKit] Token rejected: expired. remote_addr=%s", request.remote_addr
        )
        return jsonify({"error": "Token expired."}), 400
    except TokenReplayError:
        # TokenReplayError MUST precede TokenInvalidError since it is a subclass.
        logger.warning(
            "[AuthKit] Token rejected: replay detected (jti already consumed). remote_addr=%s",
            request.remote_addr,
        )
        return jsonify({"error": "Token already used."}), 403
    except TokenInvalidError:
        # Invalid signature: may indicate a forgery attempt.
        logger.warning(
            "[AuthKit] Token rejected: invalid. remote_addr=%s", request.remote_addr
        )
        return jsonify({"error": "Invalid token."}), 401
    except AuthKitError as exc:
        # RoleEscalationError, UserSyncError, TenantResolutionError, etc.
        logger.error(
            "[AuthKit] SSO failure: %s. remote_addr=%s",
            type(exc).__name__,
            request.remote_addr,
        )
        return jsonify({"error": "Authentication failed.", "detail": str(exc)}), 400
    except RuntimeError as exc:
        logger.error("[AuthKit] Runtime configuration error: %s", exc)
        return jsonify({"error": "Invalid server configuration."}), 500

    # ── 4. Session fixation ───────────────────────────────────────────────────
    # session.clear() invalidates any pre-existing session (protection against
    # session fixation: an attacker cannot force a known session ID).
    # The tenant_id is rewritten AFTER clear() so it survives this operation.
    # It was placed in the ContextVar by authenticate_sso() — re-read here.
    session.clear()
    flask_login.login_user(user, remember=False, fresh=True)

    # Persist the tenant in the HMAC-signed server session after session fixation.
    # Required for rehydration by the global before_request hook on all subsequent
    # requests.
    _tenant = TenantContext.get_tenant_or_none()
    if _tenant:
        session["_sak_tenant"] = _tenant

    _sub_prefix = (getattr(user, "username", None) or "?")[:8]
    logger.info(
        "[AuthKit] Session created successfully: sub=%s… remote_addr=%s",
        _sub_prefix,
        request.remote_addr,
    )

    # ── 5. Final redirect_to validation (defense in depth) ───────────────────
    try:
        validate_redirect_path(redirect_to)
    except ValidationError:
        logger.warning(
            "[AuthKit] Invalid redirect_to after auth (detected in defense): rejected. "
            "remote_addr=%s",
            request.remote_addr,
        )
        return jsonify({"error": "Invalid redirect_to: relative path required."}), 400

    # ── 6. Redirect ───────────────────────────────────────────────────────────
    return redirect(redirect_to, code=302)


def _get_security_manager() -> Any:
    """Extract the Superset SecurityManager from the current Flask application.

    Raises:
        RuntimeError: If ``current_app.appbuilder`` or ``appbuilder.sm`` is missing.
    """
    appbuilder = getattr(current_app, "appbuilder", None)
    if appbuilder is None:
        raise RuntimeError(
            "current_app.appbuilder is None — "
            "called outside Flask context or Flask-AppBuilder not initialized."
        )
    sm = getattr(appbuilder, "sm", None)
    if sm is None:
        raise RuntimeError(
            "appbuilder.sm is None — SecurityManager not initialized by FAB."
        )
    return sm
