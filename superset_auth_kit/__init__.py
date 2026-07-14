"""superset-auth-kit — Transparent SSO and Deep Embed for Apache Superset OSS.

Reference version: Apache Superset 6.1.0 / FAB 5.0.2 / PyJWT 2.x / Python 3.10+
"""

from __future__ import annotations

__version__ = "0.1.0"

from superset_auth_kit.exceptions import (
    AuthKitError,
    InvalidRedirectError,
    RoleEscalationError,
    RoleNotAllowedError,
    TenantResolutionError,
    TokenExpiredError,
    TokenInvalidError,
    UserSyncError,
)
from superset_auth_kit.providers._base import Identity, IdentityProvider
from superset_auth_kit.providers.jwt import ClaimMapping, JwtProvider
from superset_auth_kit.sync.fingerprint import IdentityFingerprint
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.sync.user_syncer import SecurityManagerProtocol, UserSyncer
from superset_auth_kit.tenant.context import TenantContext

# Integration layer — imported conditionally so that flask/marshmallow are not required
# in environments that only use the core logic layer.
try:
    from superset_auth_kit.security.manager import build_manager
    from superset_auth_kit.security.session import SessionFactory
    from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
    from superset_auth_kit.api.schemas import SsoRequestSchema, validate_redirect_path
    _INTEGRATION_AVAILABLE = True
except ImportError:
    _INTEGRATION_AVAILABLE = False  # type: ignore[assignment]

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "AuthKitError",
    "TokenExpiredError",
    "TokenInvalidError",
    "RoleEscalationError",
    "RoleNotAllowedError",
    "TenantResolutionError",
    "UserSyncError",
    "InvalidRedirectError",
    # Providers
    "Identity",
    "IdentityProvider",
    "ClaimMapping",
    "JwtProvider",
    # Sync
    "IdentityFingerprint",
    "RoleMapper",
    "SecurityManagerProtocol",
    "UserSyncer",
    # Tenant
    "TenantContext",
    # Security & API (available if flask + marshmallow are installed)
    "build_manager",
    "SessionFactory",
    "create_sso_blueprint",
    "init_app",
    "SsoRequestSchema",
    "validate_redirect_path",
]
