# superset-auth-kit

[![PyPI version](https://img.shields.io/pypi/v/superset-auth-kit.svg)](https://pypi.org/project/superset-auth-kit/)

[![CI](https://github.com/plinxore/superset-auth-kit/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/plinxore/superset-auth-kit/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Superset](https://img.shields.io/badge/superset-6.1.x-orange)](https://superset.apache.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**superset-auth-kit** (SAK) is a Flask extension for [Apache Superset](https://superset.apache.org/)
that provides transparent JWT-based SSO and multi-tenant embedding for SaaS applications.

It integrates directly into Superset's Flask-AppBuilder security layer — no proxy, no
sidecar, no fork required.

---

## Features

- **JWT SSO** — Validate HS256, RS256, or ES256 tokens from your identity provider and
  create a Superset session in one POST request.
- **Anti-replay protection** — JTI blocklist with pluggable backends: in-memory
  (single process) or Redis (distributed).
- **Multi-tenant context** — Thread-safe and greenlet-safe tenant propagation via
  `contextvars.ContextVar` (PEP 567). Fail Closed: raises an error rather than leaking
  data across tenants.
- **Row Level Security (RLS)** — `current_tenant()` Jinja macro for SQL templates.
  Works with `cache_key_wrapper` to guarantee per-tenant cache isolation.
- **Declarative role management** — `CapabilityBundle` definitions provisioned
  idempotently into Superset's FAB database. Two production-ready bundles included:
  `DashboardConsumer` (white-label embed) and `ChartAuthor` (authoring workspace).
- **CLI** — `superset authkit provision-roles` and `superset authkit check-compat`
  for pipeline and Kubernetes `initContainer` integration.
- **Secure by default** — Admin role injection blocked, session fixation protection,
  open-redirect prevention, HMAC-signed server sessions.

---

## Compatibility

| SAK Version | Superset | Flask-AppBuilder | Python |
|-------------|----------|------------------|--------|
| 0.1.x       | 6.1.x    | 5.0.x            | 3.10+  |

---

## Installation

```bash
pip install superset-auth-kit[api]
```

Optional extras:

| Extra | Installs | Use case |
|-------|----------|----------|
| `api` | `flask`, `flask-login`, `marshmallow` | SSO endpoint |
| `redis` | `redis` | Distributed JTI blocklist |
| `cli` | `flask`, `click`, `sqlalchemy` | `provision-roles` CLI |
| `dev` | All of the above + `pytest`, `mypy` | Development |

---

## Quick Start

### 1. Configure Superset

In your `superset_config.py`:

```python
from superset.security import SupersetSecurityManager

from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
from superset_auth_kit.providers.jwt import JwtProvider
from superset_auth_kit.replay.blocklist import InMemoryJtiStore
from superset_auth_kit.security.manager import build_manager
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.tenant.context import TenantContext

# Identity provider
_provider = JwtProvider(
    secret_or_key="your-jwt-shared-secret",  # or an RSA/EC public key
    algorithms=["HS256"],
    jti_store=InMemoryJtiStore(),  # use RedisJtiStore in production
)

# IdP role -> Superset role mapping
_mapper = RoleMapper(
    mapping={"viewer": "sak__dashboard_consumer", "analyst": "sak__chart_author"},
    allowed_roles=frozenset({"sak__dashboard_consumer", "sak__chart_author"}),
    default_roles=("sak__dashboard_consumer",),
)

# Inject SAK into Superset's security layer
CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_provider,
    role_mapper=_mapper,
)

# Register the SSO endpoint blueprint
BLUEPRINTS = [create_sso_blueprint()]
FLASK_APP_MUTATOR = init_app

# Expose current_tenant() in Jinja SQL templates
JINJA_CONTEXT_ADDONS = {
    "current_tenant": TenantContext.get_tenant,
}
```

### 2. Provision roles

```bash
superset authkit provision-roles
```

This creates `sak__dashboard_consumer` and `sak__chart_author` in the FAB database.
The command is idempotent — safe to run on every deployment.

### 3. Authenticate via SSO

Your frontend sends a signed JWT to:

```http
POST /api/v1/auth/sso
Content-Type: application/json

{
  "token": "<signed-jwt>",
  "redirect_to": "/superset/dashboard/1/"
}
```

On success: `302` redirect to `redirect_to` with a Flask session cookie set.

---

## JWT Claims

The JWT must contain the following claims:

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | ✅ | Unique user identifier |
| `email` | ✅ | User email address |
| `given_name` | ✅ | First name |
| `family_name` | ✅ | Last name |
| `roles` | ✅ | List of IdP role names (strings) |
| `tenant_id` | ✅ | Tenant identifier — `^[a-zA-Z0-9_-]{1,128}$` |
| `exp` | ✅ | Expiration timestamp (standard JWT claim) |
| `iat` | recommended | Issued-at timestamp |
| `jti` | recommended | Unique token ID (enables anti-replay) |

Claim names are configurable via `ClaimMapping` in `JwtProvider`.

---

## Row Level Security

In your Superset SQL template (dataset or RLS filter):

```sql
-- Correct: tenant_id is included in BOTH the SQL filter AND the cache key
WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'
```

The `cache_key_wrapper` call ensures that the tenant value is included in the
SHA-256 cache key hash, preventing cross-tenant cache collisions.

---

## Role Management

### Built-in capability bundles

| Bundle key | FAB role name | Profile |
|------------|--------------|---------|
| `dashboard_consumer` | `sak__dashboard_consumer` | Embed-only viewer. Zero `menu_access`. Read-only. |
| `chart_author` | `sak__chart_author` | Chart and dashboard authoring. No SQL Lab or admin access. |

### CLI

```bash
# Provision all bundles
superset authkit provision-roles

# Provision specific bundles
superset authkit provision-roles --bundle dashboard_consumer

# Dry-run: show what would change without applying
superset authkit provision-roles --dry-run

# Force re-provision even if version matches
superset authkit provision-roles --force

# Check compatibility with the installed Superset version
superset authkit check-compat
```

### Versioning

Each bundle has a `version: int`. When you modify a bundle's permission graph,
increment the version. On the next `provision-roles` run, SAK detects the version
change and applies the diff automatically.

Downgrades (deploying an older bundle version over a newer database version) are
**blocked** with an explicit error — they must be an intentional explicit action,
not a silent side effect of a rollback.

---

## Configuration Reference

| Config variable | Type | Description |
|-----------------|------|-------------|
| `CUSTOM_SECURITY_MANAGER` | `type` | Required — output of `build_manager()` |
| `BLUEPRINTS` | `list` | Required — `[create_sso_blueprint()]` |
| `FLASK_APP_MUTATOR` | `callable` | Required — `init_app` |
| `JINJA_CONTEXT_ADDONS` | `dict` | Required for RLS — `{"current_tenant": TenantContext.get_tenant}` |
| `SESSION_COOKIE_SECURE` | `bool` | Recommended `True` in production |
| `SESSION_COOKIE_HTTPONLY` | `bool` | Recommended `True` |
| `SESSION_COOKIE_SAMESITE` | `str` | Recommended `"Lax"` or `"Strict"` |

### JwtProvider options

```python
JwtProvider(
    secret_or_key=...,          # str (HMAC) or RSA/EC public key PEM
    algorithms=["HS256"],       # non-empty list — required by PyJWT 2.x
    jti_store=InMemoryJtiStore(),
    claim_mapping=ClaimMapping( # optional, all fields have defaults
        sub="sub",
        email="email",
        given_name="given_name",
        family_name="family_name",
        roles="roles",
        tenant_id="tenant_id",
    ),
    leeway=0,                   # clock skew tolerance in seconds
)
```

### Redis JTI store

```python
from superset_auth_kit.replay.blocklist import RedisJtiStore
import redis

jti_store = RedisJtiStore(
    client=redis.Redis.from_url("redis://localhost:6379/0"),
    ttl=3600,  # seconds — should match your JWT max expiry
)
```

---

## Docker Compose Integration

```yaml
superset:
  image: apache/superset:latest
  environment:
    SUPERSET_CONFIG_PATH: /app/pythonpath/superset_config.py
  command: >
    bash -c "
    pip install superset-auth-kit[api,cli] &&
    superset db upgrade &&
    superset init &&
    superset authkit provision-roles &&
    superset run -p 8088 --host 0.0.0.0 --with-threads
    "
```

---

## Kubernetes / Helm

```yaml
initContainers:
  - name: provision-sak-roles
    image: "apache/superset:latest"
    command: ["superset", "authkit", "provision-roles"]
    env:
      - name: SUPERSET_CONFIG_PATH
        value: /app/pythonpath/superset_config.py
```

This guarantees provisioning completes before application pods start — the recommended
K8s pattern for data initialization.

---

## Development

```bash
git clone https://github.com/plinxore/superset-auth-kit.git
cd superset-auth-kit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run unit tests (no Docker required)
pytest tests/unit/ -v --tb=short -m "not integration"

# Run integration tests (requires Docker)
pytest tests/integration/ -v -m integration --timeout=300

# Type checking
mypy superset_auth_kit/ --ignore-missing-imports \
    --exclude 'superset_auth_kit/cli/commands\.py'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

---

## Security

- JWT algorithm confusion: `algorithms` must be a non-empty list; `"none"` is never
  accepted.
- Admin role injection: blocked at `RoleMapper` construction and `UserSyncer` runtime.
- Tenant ID: validated by regex `^[a-zA-Z0-9_-]{1,128}$` at every ContextVar write.
  `TenantResolutionError` is raised (never `None` returned) when the context is missing.
- Session fixation: `session.clear()` is called before every `login_user()`.
- Open redirect: `redirect_to` only accepts relative paths starting with `/`.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Plinxore
