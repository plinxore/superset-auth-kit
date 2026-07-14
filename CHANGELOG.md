# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-07-14

### Added

- **JWT SSO authentication** — `JwtProvider` supporting HS256, RS256, and ES256 algorithms
  via PyJWT 2.x. Configurable claim mapping (`sub`, `email`, `given_name`, `family_name`,
  `roles`, `tenant_id`). Algorithm confusion attack prevention.
- **Anti-replay protection** — JTI blocklist with two backends: `InMemoryJtiStore` (single
  process, development) and `RedisJtiStore` (distributed, production).
- **Multi-tenant context propagation** — `TenantContext` backed by `contextvars.ContextVar`
  (PEP 567). Thread-safe and greenlet-safe. Deterministic cleanup via `reset(token)`.
  Fail Closed policy: raises `TenantResolutionError` on missing context.
- **Jinja RLS integration** — `current_tenant()` function exposed via `JINJA_CONTEXT_ADDONS`.
  Compatible with `cache_key_wrapper` for deterministic multi-tenant cache key partitioning.
- **Role management subsystem** — Declarative `CapabilityBundle` definitions with versioned
  permission graphs. Idempotent diff-set reconciliation via FAB public API. Auxiliary
  `sak_role_version` table for version tracking (idempotent DDL, no Alembic dependency).
  Two built-in bundles: `DashboardConsumer` (zero `menu_access`, read-only embed) and
  `ChartAuthor` (chart and dashboard authoring, no SQL Lab or infrastructure access).
- **Role mapper** — `RoleMapper` with IdP-to-FAB role mapping, allowlist enforcement, and
  privilege escalation blocking (Admin injection prevention at construction and runtime).
- **User synchronization** — `UserSyncer` for idempotent FAB user creation and update.
  Fingerprint-based sync: updates only when identity attributes change. Inactive user
  detection with fail-closed policy.
- **Flask security manager** — `build_manager()` factory for injecting SAK into Superset
  via `CUSTOM_SECURITY_MANAGER`. `AuthKitSecurityManager.authenticate_sso()` orchestrates
  the complete SSO flow: token validation → role mapping → user sync → session setup.
  Session fixation protection (`session.clear()` before `login_user()`).
- **Secure session configuration** — `SessionFactory` with validation of security-critical
  cookie settings (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`,
  `SESSION_COOKIE_SAMESITE`). HMAC-signed server sessions.
- **SSO API Blueprint** — `POST /api/v1/auth/sso` endpoint with Marshmallow schema
  validation. Open-redirect protection: only relative paths accepted in `redirect_to`.
  Structured error responses for all exception types.
- **CLI — `superset authkit provision-roles`** — Provisions SAK roles in the FAB database.
  Supports `--bundle` (selective), `--force` (re-provision identical versions), `--dry-run`
  (simulate without mutations). Transactional with automatic rollback on failure.
- **CLI — `superset authkit check-compat`** — Verifies existence of all declared permissions
  in the Superset database. Fails with exit 1 and a detailed report if any permission is
  missing. Suitable for CI/CD and K8s `initContainer` readiness checks.
- **Architecture Decision Records** — ADR-002 (role management and reconciliation) and
  ADR-003 (multi-tenant context and data isolation) included in `docs/adr/`.
- **Unit test suite** — 156+ unit tests covering all subsystems. No Docker required.
  Integration tests (E2E against ephemeral Superset container) opt-in via `pytest -m integration`.

### Security

- JWT algorithm confusion attack prevention: `algorithms` parameter must be a non-empty
  list; `"none"` algorithm is never accepted.
- Admin role injection blocked at `RoleMapper` construction and `UserSyncer` runtime.
- Tenant ID validated by regex `^[a-zA-Z0-9_-]{1,128}$` at every write to ContextVar.
- Session fixation protection via `session.clear()` before every `login_user()`.

[0.1.0]: https://github.com/plinxore/superset-auth-kit/releases/tag/v0.1.0
