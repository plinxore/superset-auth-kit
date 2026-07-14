"""AuthKitSecurityManager — extension of SupersetSecurityManager for the SSO flow.

Dynamic factory pattern to avoid an ``apache-superset`` dependency in the
installable package's dependencies.
The class is built at runtime by inheriting from the provided base.

Usage in ``superset_config.py``:

    from superset.security import SupersetSecurityManager
    from superset_auth_kit.security.manager import build_manager
    from superset_auth_kit.providers.jwt import JwtProvider
    from superset_auth_kit.sync.role_mapper import RoleMapper

    _provider = JwtProvider(secret_or_key="...", algorithms=["HS256"])
    _mapper   = RoleMapper(
        mapping={"app_viewer": "Gamma", "app_analyst": "Alpha"},
        allowed_roles=frozenset({"Gamma", "Alpha"}),
    )

    CUSTOM_SECURITY_MANAGER = build_manager(
        SupersetSecurityManager,
        identity_provider=_provider,
        role_mapper=_mapper,
    )
"""

from __future__ import annotations

import logging
from typing import Any

from superset_auth_kit.exceptions import RoleEscalationError
from superset_auth_kit.providers._base import Identity, IdentityProvider
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.sync.user_syncer import UserSyncer
from superset_auth_kit.tenant.context import TenantContext

logger = logging.getLogger(__name__)

_ADMIN_FORBIDDEN: frozenset[str] = frozenset({"admin"})


def build_manager(
    base_class: type[Any],
    *,
    identity_provider: IdentityProvider | None = None,
    role_mapper: RoleMapper | None = None,
) -> type[Any]:
    """Build ``AuthKitSecurityManager`` on top of the provided base class.

    The ``identity_provider`` and ``role_mapper`` parameters are captured in a
    closure to guarantee immutability after construction and avoid any mutable
    class state shared between tests or multiple instances.

    Args:
        base_class: FAB/Superset SecurityManager class to extend.
            Typically ``superset.security.SupersetSecurityManager``.
        identity_provider: Instance of :class:`~superset_auth_kit.providers._base.IdentityProvider`
            used to validate incoming tokens.
        role_mapper: Instance of :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`
            configured with the IdP → Superset mapping for this deployment.

    Returns:
        ``AuthKitSecurityManager`` class inheriting from *base_class*, ready to be
        assigned to ``CUSTOM_SECURITY_MANAGER`` in ``superset_config.py``.
    """
    # Captured in closure — immutable after this call.
    _provider: IdentityProvider | None = identity_provider
    _mapper: RoleMapper | None = role_mapper

    class AuthKitSecurityManager(base_class):  # type: ignore[valid-type,misc]
        """Superset SecurityManager extended with AuthKit SSO orchestration.

        Does NOT override ``auth_user_oauth`` because our flow does not go through
        the FAB OAuth cycle (no callback, no third-party access_token).
        Exposes :meth:`authenticate_sso` instead, called by the Blueprint view.

        Security guarantees:
        - Double anti-Admin escalation block: at the Identity level (IdP claims)
          and at the RoleMapper level (final resolution).
        - The raw token is never logged.
        - The TenantContext is propagated into the ContextVar AFTER full validation.
        """

        def authenticate_sso(self, raw_token: str) -> Any:
            """Validate *raw_token*, synchronize the FAB user, and propagate the tenant.

            Full orchestration:
            1. Verify that provider and mapper are configured.
            2. Validate the token → :class:`~superset_auth_kit.providers._base.Identity`.
            3. Anti-Admin escalation block on raw IdP claims.
            4. Propagate ``tenant_id`` into :class:`~superset_auth_kit.tenant.context.TenantContext`.
            5. FAB synchronization via :class:`~superset_auth_kit.sync.user_syncer.UserSyncer`.

            Args:
                raw_token: Raw token received from the client (content never logged).

            Returns:
                FAB User object ready for ``flask_login.login_user()``.

            Raises:
                RuntimeError: ``identity_provider`` or ``role_mapper`` missing from config.
                TokenExpiredError: Token has expired.
                TokenInvalidError: Invalid signature or claims.
                RoleEscalationError: Admin role detected in IdP claims.
                TenantResolutionError: Invalid or missing ``tenant_id``.
                UserSyncError: FAB user creation or update failed.
            """
            if _provider is None:
                raise RuntimeError(
                    "identity_provider is not configured. "
                    "Pass it to build_manager(identity_provider=...) in superset_config.py."
                )
            if _mapper is None:
                raise RuntimeError(
                    "role_mapper is not configured. "
                    "Pass it to build_manager(role_mapper=...) in superset_config.py."
                )

            logger.info("[AuthKit] Token validation started")
            identity: Identity = _provider.authenticate(raw_token)

            # Layer 1: block at raw IdP claims level (before mapping).
            # If allow_native_admin=True, IdP roles in allowed_roles are exempted
            # (e.g. "sak__admin"). Any other role containing "admin" remains blocked.
            allowed_idp = _mapper.allowed_roles if (_mapper is not None and _mapper.allow_native_admin) else frozenset()
            _assert_no_admin_claim(identity, exempt_roles=allowed_idp)

            logger.info(
                "[AuthKit] Identity validated: sub=%s… tenant=%s roles=%s",
                identity.sub[:8],
                identity.tenant_id,
                identity.roles,
            )

            # Propagation into the ContextVar (thread-safe / coroutine-safe).
            # The value is also persisted in the signed server session to
            # allow rehydration by the global before_request hook
            # on subsequent requests (dashboards, chart API, etc.).
            TenantContext.set_tenant(identity.tenant_id)

            # Write to server session (HMAC-signed by SECRET_KEY).
            # Conditional: authenticate_sso is sometimes called outside a request
            # context in unit tests — must not crash.
            try:
                from flask import has_request_context, session as flask_session
                if has_request_context():
                    flask_session["_sak_tenant"] = identity.tenant_id
            except RuntimeError:
                pass  # outside Flask context — unit test case

            # FAB synchronization (find-or-create + fingerprint short-circuit).
            syncer = UserSyncer(sm=self, role_mapper=_mapper)
            user = syncer.sync(identity)

            logger.info(
                "[AuthKit] Session created successfully: sub=%s… tenant=%s",
                identity.sub[:8],
                identity.tenant_id,
            )
            return user

    AuthKitSecurityManager.__name__ = "AuthKitSecurityManager"
    AuthKitSecurityManager.__qualname__ = "AuthKitSecurityManager"
    return AuthKitSecurityManager


def _assert_no_admin_claim(
    identity: Identity,
    *,
    exempt_roles: frozenset[str] = frozenset(),
) -> None:
    """Block any attempt to inject the Admin role via IdP claims.

    Security layer upstream of :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`:
    if a role containing ``'admin'`` (case-insensitive) is present in the raw claims,
    it is either an IdP misconfiguration or an attack attempt.
    In both cases, the flow is cut immediately.

    Args:
        identity: Identity validated by the IdentityProvider, before any mapping.
        exempt_roles: IdP roles explicitly allowed to contain "admin"
            (e.g. ``sak__admin`` when ``allow_native_admin=True``).

    Raises:
        RoleEscalationError: If at least one IdP role contains a forbidden substring
            and is not in *exempt_roles*.
    """
    for role in identity.roles:
        if role in exempt_roles:
            continue
        if any(forbidden in role.lower() for forbidden in _ADMIN_FORBIDDEN):
            logger.critical(
                "[AuthKit] SECURITY — Admin escalation attempt detected at the "
                "SecurityManager level: forbidden role in IdP claims. sub=%s…",
                identity.sub[:8],
            )
            raise RoleEscalationError(
                f"IdP role {role!r} contains the forbidden substring 'admin'. "
                f"Check the IdP and RoleMapper configuration."
            )
