"""Superset configuration for integration tests.

This file is mounted into the ephemeral container via:
    SUPERSET_CONFIG_PATH=/authkit/tests/integration/superset_config_test.py

Secrets are intentionally short and predictable: for test use only.
"""
from __future__ import annotations

from superset.security import SupersetSecurityManager  # type: ignore[import-not-found]

from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
from superset_auth_kit.providers.jwt import JwtProvider
from superset_auth_kit.replay.blocklist import InMemoryJtiStore
from superset_auth_kit.security.manager import build_manager
from superset_auth_kit.sync.role_mapper import RoleMapper

# ── Test secrets ──────────────────────────────────────────────────────────────

SECRET_KEY = "test-superset-secret-key-integration-32ch"  # noqa: S105

# ── Identity provider ─────────────────────────────────────────────────────────

JWT_TEST_SECRET = "test-jwt-secret-integration"  # noqa: S105

_provider = JwtProvider(
    secret_or_key=JWT_TEST_SECRET,
    algorithms=["HS256"],
    jti_store=InMemoryJtiStore(),
)

_mapper = RoleMapper(
    mapping={"viewer": "Gamma"},
    allowed_roles=frozenset({"Gamma"}),
    default_roles=("Gamma",),
)

# ── Custom SecurityManager ────────────────────────────────────────────────────

CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_provider,
    role_mapper=_mapper,
)

# ── SSO Blueprint ─────────────────────────────────────────────────────────────

BLUEPRINTS = [create_sso_blueprint()]
FLASK_APP_MUTATOR = init_app

# ── Local SQLite database (test only) ─────────────────────────────────────────

SQLALCHEMY_DATABASE_URI = "sqlite:////app/superset_home/superset_test.db"

# ── Disable CSRF and TALISMAN for tests ──────────────────────────────────────

WTF_CSRF_ENABLED = False
TALISMAN_ENABLED = False

# ── Required features ─────────────────────────────────────────────────────────

FEATURE_FLAGS = {
    "EMBEDDED_SUPERSET": True,
    "ENABLE_TEMPLATE_PROCESSING": True,
}

# ── Tenant RLS ────────────────────────────────────────────────────────────────

from superset_auth_kit.tenant.context import TenantContext  # noqa: E402

JINJA_CONTEXT_ADDONS = {
    "current_tenant": TenantContext.get_tenant,
}
