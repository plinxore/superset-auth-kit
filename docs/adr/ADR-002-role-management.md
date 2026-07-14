# ADR-002: Role Management and Capability Reconciliation Subsystem

| Field       | Value                                                                    |
|-------------|--------------------------------------------------------------------------|
| **Status**  | Proposed                                                                 |
| **Date**    | 2026-07-01                                                               |
| **Author**  | Security and Infrastructure Architect — superset-auth-kit                |
| **Version** | 1.0                                                                      |
| **Related** | ADR-001 (JWT/SSO), ADR-003 (RLS), ADR-004 (Next.js SDK)                 |

---

## Section 0 — Scope, Assumptions, and Boundaries

### 0.1 Base Assumptions

| Invariant                      | Fixed Value                                               |
|--------------------------------|-----------------------------------------------------------|
| BI reference version           | Apache Superset 6.1.x                                     |
| Host security framework        | Flask-AppBuilder (FAB) 5.0.x                              |
| ORM layer                      | SQLAlchemy 2.x                                            |
| Integration gateway            | `superset-auth-kit` (SAK) installed and initialized       |
| Active security manager        | `AuthKitSecurityManager` (ADR-001)                        |
| Native role sovereignty        | Roles `Admin`, `Alpha`, `Gamma`, `sql_lab`, `Public`      |
|                                | are **immutable** — SAK never touches them                |

**FAB data model observed (Superset 6.1.0 / FAB 5.0.2):**

```
ab_role            : id (PK), name VARCHAR(64)
ab_permission      : id (PK), name VARCHAR(100)
ab_view_menu       : id (PK), name VARCHAR(250)
ab_permission_view : id (PK), permission_id (FK), view_menu_id (FK)
ab_permission_view_role : role_id (FK), permission_view_id (FK)
```

Critical observation: the `ab_role` model has **no metadata fields** (no `extra_json`,
no `description`, no `version`). Any versioning strategy must therefore rely on an
auxiliary table managed by SAK.

### 0.2 Non-Goals (Out of Scope)

The following topics are **explicitly excluded** from this document:

- Row Level Security architecture and `tenant_id` context propagation (→ ADR-003).
- JWT signature, validation, and claim mapping mechanism (→ ADR-001).
- SSO Server-to-Server exchange flow and Next.js frontend SDK (→ ADR-004).
- Automatic provisioning of Datasets, database connections, or data schemas.
- User management (creation, synchronization) — covered by `UserSyncer`.

---

## Section 1 — Architecture and Business Intent

### 1.1 Modular Organization

#### Analysis of candidate structures

| Candidate structure | Evaluation |
|---------------------|-----------|
| Monolithic `roles.py` | Rapid maintenance debt; hard to unit-test |
| `roles/` with 2–3 files | Sufficient for v1 but does not separate resolver/provisioner |
| `roles/` with 4 responsibilities | Aligned with SRP; independent test cycle per layer |
| Separate `capabilities/` module | Over-engineering; does not match Python domain conventions |

#### Chosen layout

```
superset_auth_kit/
└── roles/
    ├── __init__.py               # Public re-exports
    ├── definitions.py            # Source of Truth: CapabilityBundles and their versions
    ├── capability_resolver.py    # Translates business intent → frozenset of PermSpec
    ├── role_provisioner.py       # Applies a bundle to the FAB database (transactional)
    └── role_reconciler.py        # Orchestrates version detection and lifecycle
```

**Rationale:**

- `definitions.py` is the only file that needs to change when permissions evolve. It
  serves as the declarative "source of truth", analogous to a Terraform manifest.
- `capability_resolver.py` is **stateless and pure**: it never touches the database.
  This makes it testable via `pytest` without a Docker fixture, in milliseconds.
- `role_provisioner.py` isolates all SQLAlchemy/FAB operations in a single layer.
  Session injection allows isolated testing against an in-memory SQLite database.
- `role_reconciler.py` is the single public entry point for the subsystem. It orchestrates
  the other three layers and manages the `sak_role_version` versioning table.

This separation guarantees that modifying the permission graph (in `definitions.py`)
requires no changes to provisioning or reconciliation code.

#### Auxiliary versioning table

Since `ab_role` has no metadata fields, SAK manages its own table:

```sql
CREATE TABLE IF NOT EXISTS sak_role_version (
    role_name       VARCHAR(64)  NOT NULL PRIMARY KEY,
    bundle_key      VARCHAR(64)  NOT NULL,
    bundle_version  INTEGER      NOT NULL,
    provisioned_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);
```

This table is created by `role_provisioner.py` on the first call via
`CREATE TABLE IF NOT EXISTS` (idempotent DDL, without Alembic, to avoid polluting
the Superset migration history).

---

### 1.2 Business Intent Abstraction

The core of the package is **completely agnostic of low-level FAB permissions**. It
exposes two pure SaaS business intents, modeled as versioned `CapabilityBundle` objects.

#### `definitions.py` data model

```python
@dataclass(frozen=True)
class PermSpec:
    """Canonical (FAB action, FAB view_menu) pair."""
    action: str
    view_menu: str

@dataclass(frozen=True)
class CapabilityBundle:
    """Versioned business intent → FAB permission graph."""
    key: str                            # stable identifier (snake_case)
    version: int                        # incremented with each graph modification
    role_name: str                      # SAK role name in the database (sak__ prefix)
    description: str                    # embedded documentation
    permissions: frozenset[PermSpec]    # target graph, immutable
```

#### Intent 1: `DashboardConsumer`

**Profile**: End SaaS user consuming a specific report via an embedded iframe.
The interface is fully hidden (white-label). No navigation, no writes.

**Provisioned FAB role**: `sak__dashboard_consumer` — Current version: **1**

**Construction principle**: strict subset of Gamma, stripped of all write access
and navigation. Does NOT derive from Gamma (no runtime copy) — the graph is
declared statically in `definitions.py`.

| Category | FAB Action | FAB ViewMenu | Justification |
|-----------|-----------|--------------|---------------|
| **Dashboard read access** | `can_read` | `Dashboard` | Dashboard display |
| | `can_read` | `EmbeddedDashboard` | Embed token config |
| | `can_read` | `Chart` | Dashboard components |
| | `can_read` | `Dataset` | Datasource metadata |
| | `can_read` | `Database` | Schema reading for drilldown |
| | `can_read` | `Explore` | Exploration metadata |
| | `can_read` | `Tag` | Associated tags |
| | `can_read` | `Theme` | Visual theme |
| | `can_read` | `AdvancedDataType` | Advanced types |
| | `can_read` | `AvailableDomains` | Available domains |
| | `can_read` | `RowLevelSecurity` | Active RLS config read |
| **Interactive state** | `can_read` | `DashboardFilterStateRestApi` | Interactive filters |
| | `can_write` | `DashboardFilterStateRestApi` | Local filter state write |
| | `can_read` | `DashboardPermalinkRestApi` | Permalink read |
| | `can_write` | `DashboardPermalinkRestApi` | Share permalink generation |
| | `can_read` | `ExploreFormDataRestApi` | Exploration form |
| | `can_write` | `ExploreFormDataRestApi` | Local exploration state |
| | `can_read` | `ExplorePermalinkRestApi` | Exploration permalink |
| | `can_write` | `ExplorePermalinkRestApi` | Permalink generation |
| **Embedded navigation** | `can_explore` | `Superset` | Explore entry point |
| | `can_explore_json` | `Superset` | JSON data for charts |
| | `can_dashboard` | `Superset` | Dashboard view |
| | `can_dashboard_permalink` | `Superset` | Permalink navigation |
| | `can_get_embedded` | `Dashboard` | Embed config retrieval |
| | `can_fetch_datasource_metadata` | `Superset` | Column metadata |
| **Datasource** | `can_get` | `Datasource` | Data for charts |
| | `can_external_metadata` | `Datasource` | External schema |
| | `can_external_metadata_by_name` | `Datasource` | Schema by name |
| | `can_get_drill_info` | `Dataset` | Drill-through info |
| **Utility APIs** | `can_get` | `MenuApi` | Meta-navigation |
| | `can_get` | `OpenApi` | OpenAPI schema |
| | `can_query` | `Api` | Data queries |
| | `can_query_form_data` | `Api` | Form data |
| | `can_time_range` | `Api` | Time range calculation |
| | `can_invalidate` | `CacheRestApi` | Cache invalidation |
| | `can_list` | `AsyncEventsRestApi` | Async events |
| **Interaction** | `can_drill` | `Dashboard` | Drill-through |
| | `can_view_chart_as_table` | `Dashboard` | Table view |
| | `can_view_query` | `Dashboard` | SQL query view |
| | `can_put_chart_customizations` | `Dashboard` | Visual settings |
| | `can_log` | `Superset` | Activity logging |
| | `can_language_pack` | `Superset` | i18n |
| | `can_file_handler` | `Superset` | Static file handling |
| | `can_recent_activity` | `Log` | Activity history |
| | `can_list` | `DynamicPlugin` | Chart plugins |
| | `can_show` | `DynamicPlugin` | Plugin display |
| | `can_show` | `SwaggerView` | API documentation |
| **System APIs** | `can_read` | `CurrentUserRestApi` | User profile |
| | `can_write` | `CurrentUserRestApi` | Profile update |
| | `can_read` | `SecurityRestApi` | CSRF token |
| | `can_read` | `security` | Security resources |
| | `can_read` | `user` | User data |
| | `can_read` | `Task` | Async tasks |
| **Profile** | `can_userinfo` | `UserDBModelView` | User info |
| | `can_this_form_get` | `ResetMyPasswordView` | Password form |
| | `can_this_form_post` | `ResetMyPasswordView` | Password submission |
| | `resetmypassword` | `UserDBModelView` | Password reset |
| **Tags** | `can_list` | `Tags` | Tag list |
| | `can_read` | `Tag` | *(already above)* |
| | `can_tags` | `TagView` | Tag view |

**Zero `menu_access`** — Fundamental property of the `DashboardConsumer` bundle.

**Explicit exclusions vs native Gamma role:**

| Excluded permission | Reason for exclusion |
|-------------------|------------------------------|
| `can_write\|Chart` | Read-only — no chart modification |
| `can_write\|Dashboard` | Read-only — no dashboard modification |
| `can_write\|Tag` | No taxonomy modification |
| `can_write\|Theme` | No theme modification |
| `can_csv\|Superset` | Raw data exfiltration prevention |
| `can_export\|Chart` | Same |
| `can_export\|Dashboard` | Same |
| `can_slice\|Superset` | No chart creation (reserved for ChartAuthor) |
| `can_export_streaming_csv\|SQLLab` | No SQL Lab access |
| `can_cache_dashboard_screenshot\|Dashboard` | No server-side capture |
| `can_export_as_example\|Dashboard` | No export |
| `can_delete_embedded\|Dashboard` | No embed management |
| `can_bulk_create\|Tag` | No bulk tag creation |
| `can_share_chart\|Superset` | Sharing disabled (controlled embedded context) |
| `can_share_dashboard\|Superset` | Same |
| `can_tag\|Chart`, `can_tag\|Dashboard` | No taxonomy modification |
| `can_add\|UserRegistrationsRestAPI` | User management out of scope |
| `can_delete\|UserRegistrationsRestAPI` | Same |
| `can_edit\|UserRegistrationsRestAPI` | Same |
| `can_list\|UserRegistrationsRestAPI` | Same |
| `can_show\|UserRegistrationsRestAPI` | Same |
| `can_list\|SavedQuery` | No access to saved queries |
| All `menu_access` | Full white-label — zero visible navigation |

---

#### Intent 2: `ChartAuthor`

**Profile**: SaaS analyst with the right to design, modify, and save charts
in the Superset workspace. Can create dashboards and manage their charts.
Cannot access infrastructure (DB connections, SQL Lab, CSS Templates).

**Provisioned FAB role**: `sak__chart_author` — Current version: **1**

**Construction principle**: superset of `DashboardConsumer`, more restrictive
than `Alpha`. Includes write capabilities on Chart and Dashboard, with navigation
limited to business menus. **Never inherits from Gamma or Alpha at runtime.**

**Additional permissions vs `DashboardConsumer`:**

| Category | FAB Action | FAB ViewMenu | Justification |
|-----------|-----------|--------------|---------------|
| **Chart creation/editing** | `can_write` | `Chart` | Chart creation and modification |
| | `can_slice` | `Superset` | Chart creation entry point |
| | `can_export` | `Chart` | Chart definition export |
| | `can_save` | `Datasource` | Chart datasource config save |
| | `can_validate_expression` | `Datasource` | Calculated expression validation |
| | `can_samples` | `Datasource` | Data preview |
| | `can_get_column_values` | `Datasource` | Column values (filters) |
| **Dashboards** | `can_write` | `Dashboard` | Dashboard modification and organization |
| | `can_export` | `Dashboard` | Dashboard definition export |
| | `can_export_as_example` | `Dashboard` | Example export |
| | `can_cache_dashboard_screenshot` | `Dashboard` | Thumbnail generation |
| | `can_delete_embedded` | `Dashboard` | Embed configuration management |
| | `can_share_chart` | `Superset` | Chart sharing |
| | `can_share_dashboard` | `Superset` | Dashboard sharing |
| **Tags and annotation** | `can_write` | `Tag` | Taxonomy modification |
| | `can_tag` | `Chart` | Tag charts |
| | `can_tag` | `Dashboard` | Tag dashboards |
| | `can_bulk_create` | `Tag` | Bulk creation |
| | `can_read` | `Annotation` | Read annotations |
| **Saved queries** | `can_list` | `SavedQuery` | Query access (without SQL Lab UI) |
| **CSS read** | `can_read` | `CssTemplate` | CSS template reading (no write) |
| **Chart CSV** | `can_csv` | `Superset` | CSV export from a chart |
| **Themes** | `can_write` | `Theme` | Theme application |
| | `can_export` | `Theme` | Theme export |
| **Navigation** | `menu_access` | `Home` | Superset home page |
| | `menu_access` | `Charts` | Navigation to chart library |
| | `menu_access` | `Dashboards` | Navigation to dashboards |
| | `menu_access` | `Data` | Data dropdown (parent of Datasets) |
| | `menu_access` | `Datasets` | Navigation to datasets (read) |
| | `menu_access` | `Tags` | Navigation to tags |
| | `menu_access` | `Themes` | Navigation to themes |
| | `menu_access` | `Plugins` | Navigation to plugins |

**Explicit exclusions vs native Alpha role:**

| Excluded permission | Reason for exclusion |
|-------------------|------------------------------|
| `all_database_access` | Global DB access — out of SaaS scope |
| `all_datasource_access` | Global datasource access — out of scope |
| `can_write\|Dataset` | Dataset schema modification — admin only |
| `can_duplicate\|Dataset` | Dataset duplication |
| `can_export\|Dataset` | Dataset definition export |
| `can_get_or_create_dataset\|Dataset` | Implicit dataset creation |
| `can_write\|CssTemplate` | Global CSS modification — admin only |
| `can_write\|Annotation` | Annotation creation — out of scope |
| `can_write\|ReportSchedule` | Report scheduling — out of scope |
| `can_read\|ReportSchedule` | Same (out of scope) |
| `can_upload\|Database` | File upload into DB — security risk |
| `can_import_\|ImportExportRestApi` | Global import — admin only |
| `can_export\|ImportExportRestApi` | Global export — admin only |
| `can_export_streaming_csv\|SQLLab` | SQL Lab — out of scope |
| `menu_access\|Databases` | DB connection management — admin only |
| `menu_access\|SQL Lab` | SQL Lab — out of scope |
| `menu_access\|Alerts & Report` | Scheduling — out of scope |
| `menu_access\|Annotation Layers` | Annotation management — out of scope |
| `menu_access\|CSS Templates` | Global CSS management — out of scope |
| `menu_access\|Manage` | General administration — out of scope |
| `menu_access\|Action Log` | Audit — out of scope |
| `menu_access\|Tasks` | Server task management — out of scope |

---

## Section 2 — Technical Analysis and Graph Resolution

### 2.1 Anchor Point Trade-off

Four provisioning mechanisms were evaluated across four execution contexts.

#### Comparative analysis

| Criterion | A — Flask Startup Hook (`FLASK_APP_MUTATOR`) | B — Dedicated SAK CLI (`superset authkit provision-roles`) | C — Standalone Script (Init Container) | D — Alembic Migration |
|---------|------|------|------|------|
| **Trigger** | Automatic on every startup | Manual or pipeline | Manual or init container | Automatic on `db upgrade` |
| **Local dev** | ✅ No additional action | ⚠️ Extra command after init | ❌ Requires Docker or separate script | ✅ Integrated into `superset db upgrade` |
| **CI/CD** | ⚠️ Triggered only if Superset starts | ✅ Explicit targeted pipeline step | ✅ Separate job, rollback possible | ⚠️ Mixes schema migration and data |
| **Docker Compose** | ✅ Automatic | ⚠️ Command override in `command:` | ❌ `initContainer` overhead unavailable | ✅ Via `superset db upgrade` |
| **Kubernetes (Helm)** | ⚠️ Runs in each worker pod | ✅ Ideal for K8s `initContainer` | ✅ Dedicated K8s Job with retry | ❌ Alembic migrations must not modify business data |
| **Multi-worker safety** | ❌ Race condition if N workers provision in parallel | ✅ Single atomic job | ✅ Same | — |
| **Observability** | ❌ Log mixed with app startup | ✅ Dedicated output, exploitable exit code | ✅ Same | ⚠️ Alembic log hard to read |
| **Idempotence** | ✅ If well implemented | ✅ Native (reconciliation principle) | ✅ Same | ✅ `IF NOT EXISTS` migration |
| **Rollback** | ❌ Application rollback — complex | ✅ Exit 1 + transactional SQL rollback | ✅ Same | ⚠️ Alembic downgrade unreliable on data |
| **Separation of concerns** | ❌ Mixes infra init and runtime startup | ✅ Clear infra/runtime separation | ✅ Same | ❌ Migrations ≠ data provisioning |

#### Analysis by context

**Local development:**
Option B requires an additional command (`superset authkit provision-roles`) after
`superset db upgrade && superset init`. This overhead is acceptable and can be integrated
into a `Makefile` or into the `command:` of a `docker compose` service. Option A is more
comfortable but introduces a race condition risk if the developer starts multiple workers.

**CI/CD (GitHub Actions, GitLab CI):**
Option B integrates naturally as a pipeline step:
```yaml
- name: Provision SAK roles
  run: docker exec superset superset authkit provision-roles --bundle dashboard_consumer chart_author
```
Exit code 1 fails the pipeline cleanly. No other mechanism provides this level of control.

**Docker Compose (docker-stacks):**
```yaml
superset:
  command: >
    bash -c "
    superset db upgrade &&
    superset init &&
    superset authkit provision-roles &&
    superset run -p 8088 --host 0.0.0.0 --with-threads
    "
```
Sequential, atomic, readable. Option A (`FLASK_APP_MUTATOR`) also works but is
less explicit and introduces startup latency in multi-worker environments.

**Kubernetes / Helm Charts:**
Option B is canonical via a Kubernetes `initContainer`:
```yaml
initContainers:
  - name: provision-sak-roles
    image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
    command: ["superset", "authkit", "provision-roles"]
    env:
      - name: SUPERSET_CONFIG_PATH
        value: /app/pythonpath/superset_config.py
```
This guarantees that provisioning is complete and validated **before** application
pods start. This is the recommended K8s pattern for any data initialization.

#### Strong recommendation

> **ADR-201 — Decision**: The chosen mechanism is the **dedicated CLI command**
> `superset authkit provision-roles`, implemented via the Flask/Superset CLI extension.
> It is the **sole** entry point for SAK role provisioning.
>
> An optional startup hook (`FLASK_APP_MUTATOR`) may be enabled **in development mode
> only** (`SAK_AUTO_PROVISION=true`), protected by a distributed lock (Redis) to avoid
> multi-worker race conditions. It is **disabled by default in production**.

---

### 2.2 Deterministic Resolution of the FAB Permission Graph

#### Analysis of the FAB public API

Flask-AppBuilder 5.0.x exposes the following primitives in `BaseSecurityManager`, which
constitute the **stable public API**:

```python
sm.add_role(name: str) -> Role | None
sm.find_role(name: str) -> Role | None
sm.update_role(pk: int, name: str) -> Role | None
sm.get_all_roles() -> list[Role]
sm.get_role_permissions(role: Role) -> set[tuple[str, str]]
sm.get_db_role_permissions(role_id: int) -> list[PermissionView]

sm.add_permission_view_menu(permission_name: str, view_menu_name: str) -> PermissionView
sm.find_permission_view_menu(permission_name: str, view_menu_name: str) -> PermissionView | None
sm.add_permission_role(role: Role, perm_view: PermissionView) -> None
sm.del_permission_role(role: Role, perm_view: PermissionView) -> None
```

**Finding**: The entire provisioning cycle can be achieved exclusively via these
public methods. No internal inspection of the FAB ORM model or SQLAlchemy relations
is necessary.

#### What is internal vs what is stable

| Element | Nature | Breaking risk |
|---------|--------|-------------------|
| API `sm.add_role`, `sm.find_role`, etc. | FAB documented public API | Low (FAB SemVer) |
| Action names (`can_read`, `can_write`, `menu_access`, etc.) | **Superset internal** | Moderate — changes between major versions |
| ViewMenu names (`Dashboard`, `Chart`, `Superset`, etc.) | **Superset internal** | Moderate — possible renames |
| ORM model `ab_role`, `ab_permission_view`, etc. | FAB internal | High if accessed directly |
| ORM joins `role.permissions`, `pv.permission.name` | Semi-public | Moderate |

**Conclusion**: Action and ViewMenu names are the main source of fragility.
They constitute a **compatibility surface** to monitor across Superset versions.
The bundle versioning strategy (Section 3.2) addresses exactly this risk.

#### Permission graph resolution algorithm

Resolution operates in three phases in `capability_resolver.py`:

**Phase 1 — Declarative projection → PermSpec set**

```
INPUTS  : CapabilityBundle (immutable, declared in definitions.py)
OUTPUTS : frozenset[PermSpec]  (action, view_menu pairs)
```

The resolver applies no logic — it directly returns `bundle.permissions`.
No DB connection, no FAB dependency.

**Phase 2 — Materialization into FAB PermissionView**

```
INPUTS  : frozenset[PermSpec], SQLAlchemy session
OUTPUTS : dict[PermSpec, PermissionView]
```

For each `PermSpec(action, view_menu)`:
1. `pv = sm.find_permission_view_menu(action, view_menu_name)` — look up in database.
2. If `pv is None` → `pv = sm.add_permission_view_menu(action, view_menu_name)` — create.
3. Always within the same SQLAlchemy transaction.

**Phase 3 — Diff reconciliation**

```
INPUTS  : target FAB role, dict[PermSpec → PermissionView] (target), session
OUTPUTS : (added: int, removed: int)
```

```
current_pvs = set(sm.get_db_role_permissions(role.id))
target_pvs  = set(resolved.values())

to_add      = target_pvs - current_pvs   → sm.add_permission_role(role, pv)
to_remove   = current_pvs - target_pvs   → sm.del_permission_role(role, pv)
```

This set-based diff is **deterministic**: the same target state always produces the same
result, regardless of the initial state.

#### Isolation and sovereignty constraint

SAK roles follow a strict naming convention: **`sak__` prefix**.

```
sak__dashboard_consumer
sak__chart_author
```

Isolation consequence:
- SAK **never** inspects the permissions of native roles (`Gamma`, `Alpha`, etc.).
- SAK **never** modifies the permissions of native roles.
- The diff (to_remove) only covers roles prefixed with `sak__`.
- A `superset init` cannot alter SAK roles (FAB only touches its own native roles).

#### Tightness target verification

**DashboardConsumer — zero `menu_access`:**
Verified by construction in `definitions.py` via a postcondition assertion:
```python
assert all(ps.action != "menu_access" for ps in bundle.permissions), \
    f"DashboardConsumer MUST HAVE NO menu_access permissions"
```
This assertion runs at module load time (fail-fast on import).

**ChartAuthor — SQL Lab and infrastructure prohibition:**
Forbidden elements verified by assertion:
```python
CHART_AUTHOR_FORBIDDEN_MENUS = {
    "SQL Lab", "SQL Editor", "Databases",
    "CSS Templates", "Manage", "Alerts & Report",
    "Annotation Layers", "Action Log", "Security",
    "Row Level Security", "List Users", "List Roles",
}
assert not any(
    ps.action == "menu_access" and ps.view_menu in CHART_AUTHOR_FORBIDDEN_MENUS
    for ps in bundle.permissions
), "ChartAuthor exposes a forbidden infrastructure menu"
```

---

## Section 3 — Lifecycle, Versioning, and Reconciliation

### 3.1 Determinism, Versioning, and Transactionality

#### Versioning protocol

Versioning relies on the `sak_role_version` table and the `bundle_version` field
of each `CapabilityBundle` in `definitions.py`.

**`bundle.version` increment rule:**

| Change in `definitions.py` | Required action |
|----------------------------------|---------------|
| Adding a permission | `bundle.version += 1` |
| Removing a permission | `bundle.version += 1` |
| Renaming a ViewMenu (Superset compat) | `bundle.version += 1` |
| Modifying `role_name` | New bundle (do not reuse the name) |
| Modifying `description` only | No increment (non-breaking) |

#### Reconciliation algorithm (role_reconciler.py)

```
function reconcile_bundle(bundle: CapabilityBundle, force: bool = False):

  1. READ VERSION FROM DATABASE
     stored = SELECT bundle_version FROM sak_role_version
              WHERE role_name = bundle.role_name

  2. DECISION BY COMPARISON
     if stored IS NULL             → [INITIAL PROVISION]   goto PROVISION
     if bundle.version == stored   → [IDENTICAL]
         if force                  → goto PROVISION
         else                      → return (0, 0) [skip]
     if bundle.version > stored    → [UPGRADE]             goto PROVISION
     if bundle.version < stored    → [DOWNGRADE]
         logger.critical("Downgrade attempt detected!")
         raise RoleVersionDowngradeError(
             f"Stored version {stored} > bundle version {bundle.version}"
         )

  3. PROVISION (transactional)
     BEGIN TRANSACTION (SQLAlchemy session)
     try:
       role = sm.find_role(bundle.role_name)
       if role is None:
           role = sm.add_role(bundle.role_name)

       resolved = resolver.resolve(bundle, sm)   # Phase 2 materialization
       (added, removed) = provisioner.apply_diff(role, resolved, sm)  # Phase 3

       UPSERT sak_role_version
         SET bundle_key=bundle.key, bundle_version=bundle.version, provisioned_at=NOW()
         WHERE role_name=bundle.role_name

       COMMIT
     except Exception as e:
       ROLLBACK
       raise RoleProvisioningError(f"Provisioning of {bundle.role_name!r} failed: {e}") from e

  4. RETURN
     return ProvisioningResult(role_name, added, removed, version=bundle.version)
```

#### State machine by case

**Case 1 — Identical version (v_bundle == v_db) without `--force`**

```
Result: immediate skip (0 additional SQL reads on permissions)
Log   : INFO - Role sak__dashboard_consumer v1 already up to date, skip.
Effect: No database modification. O(1) idempotent provisioning.
```

**Case 2 — Upgrade (v_bundle > v_db)**

```
Example: bundle moves from v1 to v2 (one permission added, two removed)
Result : diff set applied, 1 add + 2 del, version updated in database.
Log    : INFO - Upgrading sak__dashboard_consumer v1 → v2 (+1, -2 permissions).
Guarantee: User assignments (ab_user_role) are preserved.
           Only the role content (ab_permission_view_role) changes.
```

**Case 3 — Downgrade (v_bundle < v_db)**

```
Example: deploying an old application image on an already-migrated DB.
Result : EXCEPTION raised, transaction not started, immediate rollback.
Log    : CRITICAL - Downgrade detected: database at v2, bundle at v1.
          Check your deployment image. No modifications applied.
Justification: A downgrade could reintroduce permission vulnerabilities
          fixed in a later version. It must be an explicit decision,
          not a silent side effect.
```

**Case 4 — Initial provision (role absent from sak_role_version)**

```
Result : Role created via sm.add_role(), entire permission graph applied,
         inserted into sak_role_version.
Log    : INFO - Initial provision sak__dashboard_consumer v1 (N permissions).
```

#### Transactional security

The entire provisioning routine executes within **a single SQLAlchemy transaction
per bundle**. The FAB session (`db.session`) is used directly, without intermediate
partial commits.

```
BEGIN
  ├─ sm.add_role()               # DDL via ORM — if necessary
  ├─ sm.add_permission_view_menu()  ×N  # CREATE OR IGNORE
  ├─ sm.add_permission_role()   ×M  # INSERT ab_permission_view_role
  ├─ sm.del_permission_role()   ×P  # DELETE ab_permission_view_role
  └─ UPSERT sak_role_version
COMMIT  (or ROLLBACK on any exception)
```

**Guarantee of no corrupted role**: if the `sm.add_permission_role()` operation fails
on the N-th permission (integrity constraint, network timeout), the `ROLLBACK` restores
the role to its pre-transaction state. The `sak_role_version` entry is not updated.
The next `provision-roles` run will retry the complete operation.

---

### 3.2 Compatibility and Evolution Strategy

#### Scenario A — Disappearance of a FAB permission

*Example: Superset 6.2 renames `can_explore_json` to `can_chart_data` on the
`Superset` resource.*

**Detection:**

```python
# In capability_resolver.py, Phase 2:
pv = sm.find_permission_view_menu(action, view_menu_name)
if pv is None:
    raise PermissionNotFoundError(
        f"Permission ({action!r}, {view_menu_name!r}) absent from Superset "
        f"{superset_version}. Update definitions.py."
    )
```

The `provision-roles` command fails with exit 1 and an explicit message. The deployment
stops (in CI/CD) or the K8s pod does not start (initContainer).

**Correction process:**

1. Identify the new name via `sm.get_all_view_menu()` and diff comparison.
2. Update `definitions.py` with the new `PermSpec`.
3. Increment `bundle.version`.
4. Publish a SAK release (see SemVer policy below).

**Special case — disappeared permission with no equivalent:**
If the capability no longer exists in Superset, remove the `PermSpec` from the bundle, increment
the version, and document in the CHANGELOG.

#### Scenario B — Appearance of a new view to hide

*Example: Superset 6.2 introduces a `menu_access|AI Assistant` menu.*

**SAK behavior:**
- `DashboardConsumer`: not impacted (zero `menu_access` → the new menu is not in
  the bundle → not granted by default).
- `ChartAuthor`: the new menu is not in the bundle → not granted by default.

**Default isolation property**: The diff logic (`to_remove = current - target`)
only removes permissions that SAK explicitly granted. A new Superset permission absent
from the bundle is **never automatically granted**. Isolation is therefore guaranteed
**without code modification** when new views appear.

However, if the new view is a **legitimate feature** for `ChartAuthor`
(e.g., AI integration for chart generation), it must be explicitly added to the
bundle with a version increment.

#### SAK package SemVer policy

| Change | SAK Version | Justification |
|------------|-------------|---------------|
| Fix a missing permission (bugfix) | PATCH (x.y.**Z**) | Target behavior unchanged |
| Add a business intent (new bundle) | MINOR (x.**Y**.0) | Backward compatible |
| Modify an existing bundle graph (version bump) | MINOR (x.**Y**.0) | Backward compatible — SAK re-provisions |
| Rename/remove a bundle `role_name` | MAJOR (**X**.0.0) | Breaking — existing `RoleMapper` configs must be updated |
| Add a CLI command / modify public Python API | MINOR (x.**Y**.0) | API extension |
| Break public Python API (interfaces, exceptions) | MAJOR (**X**.0.0) | Integration breaking change |
| Update supported Superset version (breaking compat) | MAJOR (**X**.0.0) | Compatibility surface change |

**Compatibility matrix (published in README):**

| SAK Version | Superset | FAB | Python |
|-------------|----------|-----|--------|
| 1.x         | 6.1.x    | 5.0.x | 3.10+ |
| 2.x (future)| 6.2.x    | 5.1.x | 3.11+ |

#### Automatic host version drift detection

SAK exposes a side-effect-free verification command:

```bash
superset authkit check-compat
```

This command:
1. Reads the Superset version (`superset.__version__`).
2. Compares against the compatibility matrix declared in SAK.
3. For each `PermSpec` of each bundle, verifies existence in the database via
   `sm.find_permission_view_menu()`.
4. Returns exit 0 if everything is consistent, exit 1 with a detailed report otherwise.

It is executed in CI at every Superset image update, before the test run.

---

## Section 4 — Decision Summary (ADR Submission)

---

### ADR-201: Provisioning Anchor Mechanism and Execution

**Title**: SAK role provisioning via dedicated CLI command and K8s initContainer

**Context**

The `superset-auth-kit` role management subsystem must execute a set of DDL-like
operations (role creation, permission assignment in FAB database) across diverse
contexts: local development, CI/CD pipeline, Docker Compose, Kubernetes.
Four mechanisms were evaluated: Flask startup hook, dedicated CLI, standalone script,
Alembic migration.

**Decision**

The primary mechanism is a **dedicated Flask CLI command** registered in the
Superset command group:

```
superset authkit provision-roles [--bundle BUNDLE_KEY ...] [--force] [--dry-run]
```

This command:
- Is the sole authorized entry point for SAK role provisioning.
- Runs in a Kubernetes `initContainer` in production.
- Is integrated into the Docker Compose `command:` in development.
- Is included as a pipeline step in CI/CD.
- Returns exit 0 (success) or exit 1 (failure with rollback), exploitable by
  orchestrators.

An optional startup hook (`SAK_AUTO_PROVISION=true` in Superset config) may be
enabled in local development only, protected by a distributed Redis lock
(`SET NX EX 30` on `sak:provision:lock`) to prevent multi-worker race conditions.
It is **disabled by default** and documented as not recommended in production.

**Justification**

- **Multi-worker safety**: The CLI command is executed once by a K8s Job or
  `initContainer`, eliminating any race condition between Gunicorn workers.
- **Observability**: Exploitable exit code by CI/CD and K8s readiness probes. Dedicated
  logs separated from the application log stream.
- **Separation of concerns**: Infrastructure provisioning (roles) is distinct from
  application runtime startup.
- **Transactionality**: On failure, SQL rollback is immediate and the orchestrator
  retries the Job (K8s) or stops the pipeline (CI/CD).

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| `FLASK_APP_MUTATOR` hook only | N-worker race condition, startup/infra mixing, not exploitable in CI |
| Standalone Python script (Init Container) | Requires maintaining a separate script; Flask context access more complex |
| Alembic migration | Alembic is designed for schema migrations, not business data provisioning. Mixes these concerns and complicates rollbacks. |

**Consequences**

- Positive: Declarative, idempotent, rollbackable, observable deployment.
- Negative: Additional step in startup scripts (Dockerfile, Helm, CI).
- Mitigation: Provision of a `Makefile` and official Helm examples in SAK documentation.

---

### ADR-202: Role Resolution Architecture and Transactionality

**Title**: Stateless set diff resolution + atomic SQLAlchemy transaction per bundle

**Context**

FAB 5.0.x does not provide a semantic API of the type "can this role view dashboards?".
Translating business intents (`DashboardConsumer`, `ChartAuthor`) into FAB permissions must
be deterministic, reversible, and protected against any partial state in the database.
The FAB `Role` model has no metadata fields for versioning.

**Decision**

The chosen architecture relies on four separate layers:

1. **`definitions.py`** — Declarative source of truth. Each `CapabilityBundle` is a
   `@dataclass(frozen=True)` containing an immutable `frozenset[PermSpec]` and a `version: int`.

2. **`capability_resolver.py`** — Stateless and pure layer. Projects a `CapabilityBundle`
   into a `frozenset[PermSpec]` (already contained in the bundle) and materializes
   FAB `PermissionView` objects via `sm.find_permission_view_menu` / `sm.add_permission_view_menu`.
   Never touches `ab_role` or `ab_permission_view_role`.

3. **`role_provisioner.py`** — Mutation layer. Calculates the diff set (target - current) and
   applies exactly `sm.add_permission_role` and `sm.del_permission_role`. All operations
   are encapsulated in the FAB session (`db.session`) without partial commits.

4. **`role_reconciler.py`** — Orchestrator. Consults `sak_role_version`, decides the
   strategy (skip / provision / raise), calls the provisioner, and updates the table
   within the same transaction.

**Versioning table**: `sak_role_version` (created by idempotent DDL on first call,
without Alembic dependency). Columns: `role_name (PK)`, `bundle_key`, `bundle_version`,
`provisioned_at`.

**Transactional guarantee**:

```
BEGIN
  [PermissionView materialization] × N
  [add_permission_role]           × M_add
  [del_permission_role]           × M_del
  [UPSERT sak_role_version]
COMMIT — or full ROLLBACK on any exception
```

No partial modification can persist: either the bundle is fully provisioned,
or the role remains in its previous state.

**Downgrade**: If `bundle.version < stored version`, a `RoleVersionDowngradeError`
is raised before the transaction opens. No mutation is attempted.

**Justification**

- **Diff set**: O(N) algorithm without nested inspection loops. Deterministic: same
  input → same output regardless of the role's history.
- **Stateless resolver**: Testable via `pytest` without a database. Target permissions
  are computed in milliseconds.
- **Public APIs only**: `sm.add_permission_view_menu`, `sm.add_permission_role`,
  `sm.del_permission_role` — no direct inspection of `ab_*` tables via SQLAlchemy ORM.
  FAB breaking risk minimized.
- **Auxiliary table**: Necessary because `ab_role` has no metadata fields
  (confirmed on FAB 5.0.2: only `id` and `name`).

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| Copy Gamma/Alpha permissions at runtime | Creates strong coupling to native roles. A `superset init` modifying Gamma could silently alter SAK roles. |
| Store version in a pseudo-PermissionView | Pollutes the `ab_permission_view` table with versioning data. Confuses FAB about available permissions. |
| Versioning in the role name (`sak__consumer_v2`) | Requires migrating user assignments at each version. Breaks user experience. |
| Partial transactions with commit per permission | A network timeout on the N-th permission leaves a role in a corrupted state. |

**Consequences**

- Positive: Idempotent, rollbackable, unit-testable without Docker, decoupled from
  native Superset roles.
- Negative: Additional `sak_role_version` table in the FAB database (acceptable, idempotent DDL).
- Sovereignty consequence: SAK roles (`sak__*`) receive no automatic permissions
  during `superset init`. This property is **desired**:
  SAK permissions are 100% under the package's control.

---

### ADR-203: Compatibility Strategy, Versioning, and Permission Lifecycle

**Title**: Package SemVer versioning + active host permission drift detection

**Context**

Apache Superset evolves regularly. Between versions (e.g., 6.1 → 6.2), FAB permissions
may disappear, be renamed, or new menus may appear requiring explicit masking. The
`superset-auth-kit` package must remain functional in the face of these changes without
compromising security or SAK role isolation.

**Decision**

Three combined mechanisms ensure lifecycle resilience:

**1 — Fail-fast at provisioning**

`capability_resolver.py` raises an explicit `PermissionNotFoundError` if a permission
declared in a bundle is absent from the Superset database, with exact context:
```
PermissionNotFoundError: ('can_explore_json', 'Superset') absent from Superset 6.2.0.
Update superset_auth_kit/roles/definitions.py and increment bundle.version.
```
This transforms a silent regression (access granted by default) into a detectable
deployment error in CI before reaching production.

**2 — Default isolation for new views**

The diff algorithm (`to_remove = current_pvs - target_pvs`) only removes what SAK
granted. A Superset permission that appeared after the bundle was deployed, not listed in
`definitions.py`, is **never granted** to SAK roles. The white-label isolation of
`DashboardConsumer` and `ChartAuthor` is guaranteed by default for new Superset features,
without SAK code modification.

**3 — Compatibility verification command**

```bash
superset authkit check-compat [--superset-version VERSION]
```

Checks: Superset version vs SAK compatibility matrix, and existence of each `PermSpec`
in the database. Exit 0 = compatible. Exit 1 = report of missing or renamed permissions.
Integrated in CI pipeline as the `test-compatibility` step executed at every Superset
image update.

**`superset-auth-kit` SemVer policy**

| Change | SemVer level | Action required by integrator |
|------------|---------------|----------------------------------|
| Missing permission bugfix in a bundle | PATCH | `pip install superset-auth-kit==x.y.Z` + `provision-roles` |
| New CapabilityBundle | MINOR | Same + optional addition in `RoleMapper` |
| Existing bundle graph modification | MINOR | Same — automatic reconciliation |
| Bundle `role_name` rename | MAJOR | Update `RoleMapper` + migrate assignments |
| Public Python API breaking change | MAJOR | Update integration code |
| Supported Superset version change | MAJOR | Update Superset image |

**Renamed permission update process (runbook)**

```
1. superset authkit check-compat              → identifies the absent permission
2. grep in Superset 6.2 source                → finds the new name
3. Edit definitions.py                        → new PermSpec, bundle.version++
4. pytest tests/unit/                         → stateless resolver validation
5. superset authkit provision-roles --dry-run → dry-run diff simulation
6. superset authkit provision-roles           → apply (transactional)
7. SAK release tag (PATCH or MINOR)
```

**Justification**

- **Fail-fast vs silent degradation**: An undetected missing permission would cause
  users to run with an incomplete permission set, possibly insufficient to display charts.
  Fail-fast transforms this silent bug into an observable operational error.
- **Consistent SemVer**: Aligns integrator expectations (projects using SAK) with
  Python open source conventions. MAJOR only for API or role name breaking changes
  guarantees maximum stability of current bundles.
- **Default isolation**: The alternative (granting all new Superset permissions to
  SAK roles by default) would be a privilege escalation vector on update.
  The principle of least privilege mandates explicit opt-in.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| Derive bundles from native roles at runtime | Strong coupling: a Superset modification to Gamma silently modifies DashboardConsumer. |
| Ignore absent permissions (log warning) | Silent regression: the user sees a degraded dashboard without a clear error. |
| Versioning tied to the Superset version (e.g., SAK 6.1.0) | Confusion between package version and Superset version. Makes independent evolution impossible. |
| Alembic to track permission changes | Over-engineering: Alembic is designed for schema migrations, not for evolving an application data graph. |

**Consequences**

- Positive: Superset update cycle detectable before production, clear SemVer policies
  for integrators, isolation guaranteed by construction.
- Negative: Each Superset version upgrade requires a `check-compat` step and
  potentially a SAK release. This overhead is structural and accepted.
- Mitigation: Automate `check-compat` in CI with Slack/GitHub Discussions notification
  on drift detection.

---

*End of document ADR-002 — superset-auth-kit Role Management and Capability Subsystem*
