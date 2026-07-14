# ADR-003: Multi-Tenant Context and Data Isolation Tightness

| Field       | Value                                                                       |
|-------------|-----------------------------------------------------------------------------|
| **Status**  | Proposed                                                                    |
| **Date**    | 2026-07-01                                                                  |
| **Author**  | Security and Infrastructure Architect — superset-auth-kit                   |
| **Version** | 1.0                                                                         |
| **Related** | ADR-001 (JWT/SSO), ADR-002 (Roles), ADR-004 (Next.js SDK)                  |

---

## Section 0 — Scope, Assumptions, and Boundaries

### 0.1 Base Assumptions

| Invariant | Fixed Value |
|-----------|-------------|
| BI version | Apache Superset 6.1.x |
| Flask framework | Flask 2.3.3 (ContextVar-backed locals — see §1.1) |
| Python runtime | Python 3.10.x (CPython) — `contextvars` stable since 3.7 |
| Gunicorn workers | Supported modes: `sync`, `gthread`, `gevent/eventlet` |
| Cache backend | Flask-Caching (Redis in production, Null or SimpleCache in dev) |
| Source of truth | `tenant_id` extracted **exclusively** from the validated JWT (ADR-001) |
| Immutability | `tenant_id` immutable for the entire lifetime of the session |

**Fundamental architectural observation — Flask 2.3 and ContextVar:**

```python
# flask/globals.py (Flask 2.3.3)
_cv_app: ContextVar[AppContext] = ContextVar("flask.app_ctx")
_cv_request: ContextVar[RequestContext] = ContextVar("flask.request_ctx")

g: _AppCtxGlobals = LocalProxy(_cv_app, "g")   # <- g is bound to the AppContext
```

`flask.g` is a `LocalProxy` on `_cv_app.get().g`. The `AppContext` contains an
`_AppCtxGlobals` instance as attribute `g`. Although Flask 2.3 already uses `ContextVar`
for its own proxies, `g` remains **bound to the AppContext**, not the RequestContext.
This distinction is central to decision ADR-301 (§1.1).

### 0.2 Execution Scope

**In-Scope:** Full lifecycle of interactive HTTP requests —
SSO authentication, dashboard loading, chart data API calls, exploration forms.

**Out-of-Scope:** Async Celery tasks, scheduled email alerts, async exports.
These are covered in section 3.3 (future extension strategy).

---

## Section 1 — Propagation, Thread-Safety, and Context Lifecycle

### 1.1 Comparative Matrix of Storage Mechanisms

#### Mechanism A — `flask.g`

`flask.g` in Flask 2.3 is a `LocalProxy` on `_cv_app.get().g`. The `AppContext`
is pushed and popped by Gunicorn on each request via `wsgi_app()` → `push()` / `pop()`.
Superficially, `g` therefore appears request-scoped.

**Fundamental problem:** `g` is an attribute of the `AppContext`, not the `RequestContext`.
If the AppContext is shared (test, background task injected into an existing context),
`g` is no longer isolated. More precisely:

- `AppContext.g` is a **mutable** and **shared** `_AppCtxGlobals` object within the
  application context. If two requests run in the same AppContext (should not happen
  in Gunicorn sync but can in tests or admin code), they share the same `g`.
- Flask 2.3 `ContextVar` (`_cv_app`) isolates AppContexts **per coroutine/thread**.
  Each Gunicorn thread has its own `_cv_app`, therefore its own `g`. But within a thread
  only one AppContext can be active at a time.
- **Residual risk:** If Superset evolves to reuse AppContexts (e.g., context pooling),
  or if a background task manually pushes an AppContext, `g` may expose data from a
  previous request.

#### Mechanism B — `threading.local`

`threading.local` isolates values per OS thread. Each Gunicorn thread has its own
storage space.

**Critical problems:**
- **Incompatible with Gevent/Eventlet workers:** Gevent monkey-patches Python threads
  with greenlets. `threading.local` is then shared between multiple coroutines on the
  same virtual thread — guaranteed cross-request contamination in async mode.
- **No clean reset mechanism:** `threading.local` has no Token concept for restoring
  a previous value. The `del value` cleanup is irreversible.
- **Incompatible with `contextvars.copy_context()`:** unit tests cannot isolate contexts
  without monkeypatching.

#### Mechanism C — `contextvars.ContextVar` (PEP 567)

`ContextVar` is the standard library contextual storage since Python 3.7. It was designed
precisely to solve the limitations of `threading.local` in asynchronous architectures.

**Properties guaranteed by the Python spec:**
- Each OS thread has its own default `Context` (copy of the parent context at creation).
- Each `asyncio.Task` receives a **copy** of its creator's `Context`. Modifications in
  the task are invisible to the creator and vice versa.
- Gevent Greenlets copy the `Context` at startup (`contextvars` is greenlet-safe since
  gevent 1.5 / greenlet 0.4.17).
- `token = ctx.set(value)` + `ctx.reset(token)` restores **exactly** the previous state
  of the ContextVar, even if other ContextVars were modified in between.

```python
# Isolation demonstration:
var = ContextVar("x", default=None)

def thread_a():
    token = var.set("tenant-A")
    time.sleep(0.1)           # <- thread_b executes during this sleep
    assert var.get() == "tenant-A"   # guaranteed isolation
    var.reset(token)

def thread_b():
    token = var.set("tenant-B")
    assert var.get() == "tenant-B"   # guaranteed isolation
    var.reset(token)
```

#### Mechanism D — Flask Session Cookie

Storing `tenant_id` in the Flask session cookie client-side.

**Eliminatory security problems:**
- The Flask session cookie is **signed but readable** (base64 + HMAC). Clients can
  read the `tenant_id` value.
- Although an attacker cannot modify the cookie without invalidating the signature,
  the `tenant_id` becomes visible client-side — violation of the server-side immutability
  principle.
- In case of cookie theft (XSS, Man-in-the-Middle), the `tenant_id` is exposed.

**Note:** This mechanism is distinct from storing the `tenant_id` **inside** the
server-side session (value persisted under the Flask-Login key), which is valid for
rehydration (see §1.2 — Initialization).

#### Decision table

| Criterion | `flask.g` | `threading.local` | `contextvars.ContextVar` | Session Cookie |
|---------|:---------:|:-----------------:|:------------------------:|:--------------:|
| Per-thread isolation Gunicorn sync | ✅ | ✅ | ✅ | ✅ |
| Per-greenlet isolation Gevent/Eventlet | ⚠️ (if AppCtx shared) | ❌ | ✅ | N/A |
| Per-task isolation asyncio | ⚠️ | ❌ | ✅ | N/A |
| Deterministic state restoration (token.reset) | ❌ | ❌ | ✅ | ❌ |
| Testability without Flask mock | ❌ | ❌ | ✅ (`copy_context`) | ❌ |
| Resistance to cross-request contamination | ⚠️ (AppCtx dependent) | ❌ | ✅ | ❌ |
| Server-side immutability | ✅ | ✅ | ✅ | ❌ |
| Superset 6.1 compatibility without patch | ✅ | ✅ | ✅ | N/A |
| Support for future workers (async) | ⚠️ | ❌ | ✅ | N/A |

**Decision: `contextvars.ContextVar` (ADR-301).**

---

### 1.2 Lifecycle, Flask Hooks, and Cleanup Guarantee Limits

#### Full lifecycle model of an HTTP request

```
+-------------------------------------------------------------------------+
|  Gunicorn Worker (thread or greenlet)                                   |
|                                                                         |
|  1. WSGI environ received -> Flask creates RequestContext + AppContext  |
|     -> _cv_request.set(rc_token), _cv_app.set(ac_token)                |
|                                                                         |
|  2. before_request (SAK global hook)                                    |
|     +----------------------------------------------------------+        |
|     | * Read tenant_id from signed server session              |        |
|     | * Regex pattern validation (fail-fast if invalid)        |        |
|     | * token = TenantContext.set_tenant(tenant_id)            |        |
|     | * Store token in g._sak_tenant_token                     |        |
|     +----------------------------------------------------------+        |
|                                                                         |
|  3. View / Handler (data access, Jinja SQL rendering)                   |
|     -> TenantContext.get_tenant() accessible anywhere in the stack      |
|                                                                         |
|  4. teardown_request (SAK global hook) -- executed IN ALL CASES        |
|     +----------------------------------------------------------+        |
|     | token = getattr(g, "_sak_tenant_token", None)            |        |
|     | if token: TenantContext.reset(token)                     |        |
|     | else:     TenantContext.clear()   # safety net           |        |
|     +----------------------------------------------------------+        |
|                                                                         |
|  5. Flask pop RequestContext -> _cv_request.reset(), _cv_app.reset()    |
+-------------------------------------------------------------------------+
```

#### Phase 1 — Initialization (before_request)

The global `before_request` hook is responsible for **rehydrating** the tenant context
from the server session for all authenticated requests after the SSO.

```python
# Conceptual logic (no implementation here)
@app.before_request
def hydrate_tenant_context():
    # 1. Check that the user is authenticated (Flask-Login)
    if not current_user.is_authenticated:
        return  # Public endpoints do not require a tenant

    # 2. Read tenant_id from the server session (server-side signed)
    #    The key "_sak_tenant" is written by the SSO flow in authenticate_sso()
    tenant_id = session.get("_sak_tenant")

    if not tenant_id:
        # Fail Closed: authenticated user without tenant -> security error
        logger.error("[AuthKit] AUDIT: User %s authenticated without tenant_id.",
                     current_user.username)
        abort(403)

    # 3. Validate and propagate into ContextVar
    token = TenantContext.set_tenant(tenant_id)  # raises TenantResolutionError if invalid
    g._sak_tenant_token = token
```

**Session write timing:** In `authenticate_sso()`, after JWT validation and before `login_user()`:
```python
session["_sak_tenant"] = identity.tenant_id   # write to signed server session
TenantContext.set_tenant(identity.tenant_id)  # ContextVar for the SSO request itself
```

The Flask session uses by default a **server-side signed** cookie (HMAC-SHA1 with
`SECRET_KEY`). The `tenant_id` is encrypted in the cookie if `SESSION_TYPE` is configured
with a server backend (Flask-Session + Redis) — recommended in production.

#### Phase 2 — Propagation

`TenantContext.get_tenant()` is callable from any level of the execution stack during
the request:
- Flask views / Blueprints
- Jinja SQL templates (via `JINJA_CONTEXT_ADDONS`)
- QueryContext processing cells
- Custom code injected via Superset hooks

#### Phase 3 — Cleanup (teardown_request)

**`reset(token)` vs `clear()` protocol:**

- `token = ctx.set(value)` records the previous state of the ContextVar.
- `ctx.reset(token)` **restores exactly** that previous state, including the case
  where the value was `None` (ContextVar never initialized in this context).
- `ctx.set(None)` via `clear()` is a safety net: it forces `None` but does not
  "restore" the state — if the previous value was a string (nested request), it would
  be overwritten.

**Chosen strategy:**
```python
@app.teardown_request
def cleanup_tenant_context(exc: BaseException | None) -> None:
    token = getattr(g, "_sak_tenant_token", None)
    if token is not None:
        TenantContext.reset(token)     # deterministic restoration
    else:
        TenantContext.clear()          # safety net: before_request did not execute
```

**Why store the token in `g`?**
The token must survive from `before_request` to `teardown_request`. `g` is the only
native request-scoped storage in Flask. Since `g` is itself backed by `ContextVar` in
Flask 2.3 (see §0.1), this storage is thread-safe and request-scoped by construction.

#### Analysis of teardown_request guarantees

Flask guarantees execution of `teardown_request` in the following scenarios:

| Scenario | teardown_request executed? | Residual security property |
|----------|:--------------------------:|----------------------------------|
| Nominal response (200, 302, 404) | ✅ Guaranteed | ContextVar properly restored |
| Uncaught Python exception | ✅ Guaranteed (`try/finally` in `RequestContext.pop()`) | ContextVar restored |
| `flask.abort(403, 404, ...)` | ✅ Guaranteed | ContextVar restored |
| SQLAlchemy timeout (Python exception) | ✅ Guaranteed | ContextVar restored |
| HTTP client disconnected during processing | ✅ Guaranteed (worker continues) | ContextVar restored |
| `SystemExit` | ✅ Guaranteed (captured by WSGI) | ContextVar restored |
| **SIGKILL / OOM Killer** | ❌ **Not guaranteed** | Process destroyed — no cross-request leaks |
| **Hard crash (Segfault, bus error)** | ❌ **Not guaranteed** | Same — the process dies |
| Gunicorn worker killed by timeout | ⚠️ SIGKILL after SIGTERM | If SIGTERM: guaranteed. If SIGKILL: not |

**Residual security property on SIGKILL:**
In the case of a SIGKILL, the Gunicorn worker process is destroyed. The `ContextVar`
containing the `tenant_id` is in process memory released by the OS. There is **no
cross-request leak** because the next worker is a different process with clean memory.
The only consequence is that the in-flight request is not completed (503 for the client).

#### Complete SSO flow with rehydration

```
REQUEST 1 -- SSO (POST /api/v1/auth/sso)
  authenticate_sso(raw_token)
    -> identity = provider.authenticate(raw_token)
    -> session["_sak_tenant"] = identity.tenant_id   <- WRITTEN TO SERVER SESSION
    -> token = TenantContext.set_tenant(identity.tenant_id)
    -> user = syncer.sync(identity)
    -> flask_login.login_user(user)
    -> redirect(redirect_to)
  [teardown_request] -> TenantContext.clear()  # blueprint teardown

REQUEST 2 -- Dashboard (GET /superset/dashboard/1/)
  [before_request] (SAK global hook)
    -> tenant_id = session.get("_sak_tenant")     <- READ FROM SESSION
    -> token = TenantContext.set_tenant(tenant_id)
    -> g._sak_tenant_token = token
  [View] -> Jinja SQL rendering -> current_tenant() -> "my-saas-tenant"
  [teardown_request] -> TenantContext.reset(token)

REQUEST 3 -- API Chart Data (POST /api/v1/chart/data)
  [before_request] -> same as request 2
  [QueryContextProcessor] -> Jinja process_template()
    -> {{ cache_key_wrapper(current_tenant()) }} -> "my-saas-tenant" + appended to extra_cache_keys
  [teardown_request] -> TenantContext.reset(token)
```

---

## Section 2 — Jinja Integration, Cache, and Threat Model

### 2.1 Jinja Injection and Degradation Policy ("Fail Closed")

#### Integration mechanism via JINJA_CONTEXT_ADDONS

```python
# In superset_config.py
JINJA_CONTEXT_ADDONS = {
    "current_tenant": TenantContext.get_tenant,
}
```

**Superset integration point:** `superset/jinja_context.py`, method
`BaseTemplateProcessor.set_context()`, line 692 (Superset 6.1.0):

```python
def set_context(self, **kwargs: Any) -> None:
    self._context.update(kwargs)
    self._context.update(context_addons())   # <- injection here
```

`context_addons()` is decorated with `@lru_cache(maxsize=LRU_CACHE_MAX_SIZE)`:

```python
@lru_cache(maxsize=LRU_CACHE_MAX_SIZE)
def context_addons() -> dict[str, Any]:
    return current_app.config.get("JINJA_CONTEXT_ADDONS", {})
```

**Analysis of `@lru_cache` + `ContextVar` interaction:**

The cache memoizes the **dict** `{"current_tenant": <bound method TenantContext.get_tenant>}`.
This function reference is stable at process level (never changes after the first call).
The cache does **not** memoize the result of calling `get_tenant()`. Each Jinja template
rendering calls `TenantContext.get_tenant()` at execution time, reading from the ContextVar
at that exact moment. The interaction is therefore correct:

```
lru_cache    -> caches the REFERENCE to get_tenant() (stable, process level)
ContextVar   -> the VALUE returned by get_tenant() changes per request
```

**API classification:** `JINJA_CONTEXT_ADDONS` is an **officially documented Superset
public API** (configuration variable documented in the official Superset documentation).

#### The `current_tenant()` macro as a pure function

`TenantContext.get_tenant()` satisfies the following properties:

| Property | Guaranteed | Mechanism |
|-----------|----------|-----------|
| Read-only | ✅ | No ContextVar mutation in `get_tenant` |
| Intra-request determinism | ✅ | The ContextVar can only be modified by `set_tenant` (single call in `before_request`) |
| SQL injection protection | ✅ | Regex validation on write: `^[a-zA-Z0-9_-]{1,128}$` — no dangerous SQL characters accepted |
| No side effects | ✅ | Only `_tenant_ctx.get()` + non-None validation |
| Thread-safety | ✅ | ContextVar is thread-safe by construction |
| CPU cost | O(1) | `ContextVar.get()` is a C-level operation in CPython |

**Execution frequency:** `current_tenant()` is called **once per SQL template** containing
the macro (once per chart when loading a dashboard). The cost is negligible.

#### Degradation policy ("Fail Closed")

```
Macro {{ current_tenant() }} called:
  +- tenant_id present in ContextVar -> returns the validated value
  +- tenant_id absent (None) -> raises TenantResolutionError
       -> Jinja2 SandboxedEnvironment propagates the exception
       -> Superset abort(500) or returns an error response
       -> No SQL query is executed with an invalid WHERE clause
```

**Absolute prohibition on returning `None`:**

A `None` return from `current_tenant()` would generate a SQL template such as:
```sql
WHERE tenant_id = 'None'   -- if implicit Jinja2 cast
WHERE tenant_id = NULL     -- if explicitly handled in template
```

The first case does not filter the current tenant's data (comparison with the string
`'None'`). The second always returns zero rows in standard SQL (NULL != NULL), or
executes a full scan without a filter. Both are **critical isolation violations**.
`TenantResolutionError` is the only correct response.

#### Jinja extension point — classification

| Extension point | Type | Breaking risk |
|------------------|------|-------------------|
| `JINJA_CONTEXT_ADDONS` (config key) | **Superset documented public API** | Low |
| `BaseTemplateProcessor.set_context()` | **Superset internal API** | Moderate (minor changes possible) |
| `context_addons()` function with `@lru_cache` | **Superset internal API** | Moderate |
| `SandboxedEnvironment` (Jinja2) | **Jinja2 public API** | Low |
| `ExtraCache.cache_key_wrapper` | **Superset internal API** | Moderate (see §2.2) |

**Recommended regression tests:** At each Superset version upgrade:
```bash
# Verify that JINJA_CONTEXT_ADDONS is still injected into the Jinja context
grep -n "context_addons\|JINJA_CONTEXT_ADDONS" /app/superset/jinja_context.py
# Verify that set_context calls context_addons()
grep -A 5 "def set_context" /app/superset/jinja_context.py
```

---

### 2.2 Identification and Multi-Tenant Partitioning of Cache Layers

#### Inventory of Superset 6.1 cache layers

Superset 6.1.x manages five distinct cache instances via `CacheManager`
(`superset/utils/cache_manager.py`):

| Instance | Config Key | Content | Tenant-dependent? |
|----------|-----------|---------|----------------------|
| `cache` | `CACHE_CONFIG` | General cache (metadata, lists) | ⚠️ Partial |
| `data_cache` | `DATA_CACHE_CONFIG` | Chart query results | ✅ **Critical** |
| `thumbnail_cache` | `THUMBNAIL_CACHE_CONFIG` | Dashboard/chart screenshots | ✅ **Critical** |
| `filter_state_cache` | `FILTER_STATE_CACHE_CONFIG` | Dashboard filter states | ✅ **Critical** |
| `explore_form_data_cache` | `EXPLORE_FORM_DATA_CACHE_CONFIG` | Exploration forms | ⚠️ Partial |

**`distributed_coordination` backend (Redis primitives):** used for distributed locks
and pub/sub — does not contain user data, not affected.

#### Analysis per layer

**`data_cache` (critical — mandatory partitioning)**

This is the SQL query results cache, directly impacted by Jinja RLS filters. The cache
key is generated in `QueryContextProcessor.query_cache_key()`:

```python
cache_key = query_obj.cache_key(
    datasource=datasource.uid,
    extra_cache_keys=extra_cache_keys,    # <- values injected from Jinja templates
    rls=security_manager.get_rls_cache_key(datasource),
    changed_on=datasource.changed_on,
)
```

`extra_cache_keys` is a list that collects values via `cache_key_wrapper`. If
`current_tenant()` is called in the SQL template **without** `cache_key_wrapper`, the
Jinja filter result is **not included in the cache key**: two different tenants would get
the same cache key, causing a cross-tenant collision.

**Correct partitioning algorithm:**

```sql
-- INCORRECT: tenant included in SQL but absent from cache key
WHERE tenant_id = '{{ current_tenant() }}'

-- CORRECT: tenant included in SQL AND in cache key
WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'
```

`cache_key_wrapper` is natively exposed in the Superset Jinja context (line 844 of
`jinja_context.py`):
```python
"cache_key_wrapper": partial(safe_proxy, extra_cache.cache_key_wrapper),
```

It calls `extra_cache.cache_key_wrapper(value)` which:
1. Appends `value` to `self.extra_cache_keys` (included in the cache key hash)
2. Returns `value` (passthrough — the value is properly inserted into the SQL)

**Classification:** `cache_key_wrapper` is a **Superset internal API** exposed via the
Jinja context. Moderate breaking risk. CI regression test:
```bash
grep -n "cache_key_wrapper" /app/superset/jinja_context.py
```

**`filter_state_cache` (critical — native partitioning)**

Filter states are stored with a UUID key (`id`) generated client-side and passed in the
URL. The cache key is `FILTER_STATE_{id}`. Two tenants with different UUIDs cannot have
a collision. Partitioning is **native** by UUID. No additional action required.

**Residual risk:** An attacker knowing another tenant's filter state UUID could attempt
to read it. Mitigation: `DashboardFilterStateRestApi` is protected by FAB access checks.
A SAK user can only access resources from their tenant (via RLS).

**`thumbnail_cache` (critical — explicit partitioning required)**

Thumbnail keys are computed in `DashboardScreenshot.get_cache_key()`:

```python
args = {
    "thumbnail_type": self.thumbnail_type,
    "digest": self.digest,          # <- hash of dashboard content
    "type": "thumb",
    "window_size": window_size,
    "thumb_size": thumb_size,
}
return hash_from_dict(args)
```

`self.digest` is computed from dashboard metadata (title, layout). If two tenants have
access to the same physical dashboard (same ID in database), their `digest` is identical
→ **possible thumbnail key collision**.

**Partitioning strategy:** The screenshot `digest` must include the `tenant_id`. This
requires overriding `DashboardScreenshot` or intercepting at the thumbnail generation
level. This override touches **Superset internal APIs** (`superset/utils/screenshots.py`).
The associated technical debt is documented in ADR-305.

**Immediate alternative:** Disable the thumbnail cache in multi-tenant environments
(`THUMBNAIL_CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}`) until full implementation.

**`explore_form_data_cache` (partial — contextual analysis)**

This cache stores exploration form state (Explore) during navigation. The key is
generated by `ExploreFormDataRestApi` from a hash of the `form_data` JSON. If the
`form_data` includes tenant-specific parameters (filters, columns), the key is naturally
different between tenants. If the `form_data` is identical (same chart, same parameters),
a collision is theoretically possible.

**Recommendation:** For `ChartAuthor`, the `form_data` includes dataset and filter
parameters that are naturally distinct per tenant. For `DashboardConsumer` (who cannot
access Explore), this cache is not exposed. **Low risk** for current bundles.

**General `cache` (partial — monitoring)**

This cache is used for metadata (dashboard lists, user lists, permissions). Most entries
are already partitioned by URL or by user. No tenant-specific partitioning is required
for the use cases covered by ADR-002.

#### Canonical partitioning algorithm

```
FOR each SQL query executed by a Superset chart:

1. The Jinja SQL template is rendered by JinjaTemplateProcessor
   with extra_cache_keys = [] (empty list, collected during rendering)

2. {{ cache_key_wrapper(current_tenant()) }} is evaluated:
   a. current_tenant() -> reads ContextVar -> "tenant-abc" (validated)
   b. cache_key_wrapper("tenant-abc") -> appends "tenant-abc" to extra_cache_keys

3. QueryObject.cache_key() is computed:
   cache_dict = {
     "datasource": datasource.uid,
     "extra_cache_keys": ["tenant-abc"],   # <- tenant included!
     "rls": security_manager.get_rls_cache_key(datasource),
     ...
   }
   hash = hash_from_dict(cache_dict)   # deterministic

4. Isolation property:
   hash("tenant-abc", ds=5, ...) != hash("tenant-xyz", ds=5, ...)
   -> NEVER a cross-tenant collision for the same data
```

**Collision elimination verification:**

Let `H(x)` be the hash function. The cache key for a QueryObject is:
`key = H(datasource_uid + extra_cache_keys + rls_clauses + ...)`.

If `extra_cache_keys` includes `tenant_id`, then for two distinct tenants A and B:
`H(..., extra_cache_keys=["tenant-A"], ...) != H(..., extra_cache_keys=["tenant-B"], ...)`
because `"tenant-A" != "tenant-B"` and `H` is collision-resistant (SHA-256 via
`hash_from_dict`). The isolation property is guaranteed by the cryptographic properties
of the hash function.

---

### 2.3 Classification and Qualification of Extension Points

| Component / Hook | API Type | Breaking risk 6.1->6.2 | Risk 6.x->7.x | Recommended CI test |
|-----------------|-----------|--------------------------|----------------|-------------------|
| `JINJA_CONTEXT_ADDONS` | ✅ **Superset documented public API** | Very low | Low | Check presence in `config.py` |
| `BLUEPRINTS` (config) | ✅ **Superset documented public API** | Very low | Low | Application startup |
| `FLASK_APP_MUTATOR` (config) | ✅ **Superset documented public API** | Very low | Low | Application startup |
| `before_request` / `teardown_request` (Flask) | ✅ **Flask documented public API** | Very low | Low | Hook unit test |
| `flask.session` (tenant read/write) | ✅ **Flask documented public API** | Very low | Low | SSO integration test |
| `context_addons()` with `@lru_cache` | ⚠️ **Superset internal API** | Moderate | Moderate | `grep "context_addons\|lru_cache" jinja_context.py` |
| `BaseTemplateProcessor.set_context()` | ⚠️ **Superset internal API** | Moderate | High | `grep "set_context.*context_addons" jinja_context.py` |
| `cache_key_wrapper` (Jinja macro) | ⚠️ **Superset internal API** | Moderate | Moderate | `grep "cache_key_wrapper" jinja_context.py` |
| `ExtraCache.extra_cache_keys` | ⚠️ **Superset internal API** | Moderate | Moderate | `grep "extra_cache_keys" jinja_context.py` |
| `DashboardScreenshot.digest` | ❌ **Superset internal API** | High | High | `grep "def get_cache_key" screenshots.py` |
| `SecurityManager.get_rls_cache_key` | ⚠️ **Stable undocumented API** | Low | Moderate | `grep "get_rls_cache_key" security/manager.py` |
| `g._rls_filter_cache` | ❌ **FAB/Superset internal API** | Moderate | High | Secure access test |
| `flask.g._sak_tenant_token` | SAK private attribute on `g` | Low (`_sak` prefix) | Low | Cleanup test |

**CI monitoring policy:**

```yaml
# .github/workflows/compat-check.yml
- name: Check Superset internal API stability
  run: |
    python -c "
    import subprocess, sys
    checks = [
      ('context_addons', 'superset/jinja_context.py'),
      ('set_context', 'superset/jinja_context.py'),
      ('cache_key_wrapper', 'superset/jinja_context.py'),
      ('get_rls_cache_key', 'superset/security/manager.py'),
    ]
    for symbol, path in checks:
      result = subprocess.run(['grep', '-n', symbol, f'/app/{path}'], capture_output=True)
      if result.returncode != 0:
        print(f'BREAKING: {symbol} absent from {path}')
        sys.exit(1)
      print(f'OK: {symbol} present in {path}')
    "
```

---

### 2.4 Data Isolation Threat Model

#### Vector 1 — Worker memory contamination

**Scenario:** A request from tenant A sets `tenant_id = "tenant-A"`. A bug in the
cleanup cycle leaves this value in the ContextVar. The next request from tenant B, on the
same thread, reads `"tenant-A"` from the ContextVar.

**Architectural countermeasures:**

| Layer | Mechanism | Effectiveness |
|--------|-----------|-----------|
| ContextVar `reset(token)` in `teardown_request` | Deterministic restoration of the previous value (None) | **Eliminates** for normal requests |
| `before_request`: systematic re-initialization | Even if a residual value exists, it is **replaced** by the session value at the start of each request | **Eliminates** — double safety net |
| Logging initial state in `before_request` | If `TenantContext.get_tenant_or_none() is not None` before hydration -> WARN | **Detective** |
| `_sak_` prefix on `g` attribute | Avoids collisions with other middlewares using `g` | **Preventive** |

The combination of `reset(token)` + `before_request` re-initialization forms a **double
safety net**: even if `teardown_request` fails (very unlikely), the `before_request` of
the next request reinitializes the context.

#### Vector 2 — Cache poisoning

**Scenario:** Tenant A's request generates cache key K and caches data DA. Tenant B's
request, for the same chart, generates the same key K (if the tenant is not in the key)
and receives DA.

**Architectural countermeasures:**

| Layer | Mechanism | Effectiveness |
|--------|-----------|-----------|
| `{{ cache_key_wrapper(current_tenant()) }}` | Includes `tenant_id` in the SHA-256 hash of the key | **Eliminates** for `data_cache` |
| ContextVar validated on write (`set_tenant`) | Guarantees the value in the key is a valid `tenant_id` | **Preventive** |
| `thumbnail_cache` disabled or partitioned | See §2.2 — patch required on `DashboardScreenshot.digest` | **Partial** (technical debt) |
| `filter_state_cache`: UUID keys | Collision impossible without knowledge of the UUID | **Eliminates** via UUID |

**Mandatory rule (documented in CONTRIBUTING.md and SQL templates):**

> Any Jinja macro using a security attribute (tenant_id, user_id) in a WHERE clause
> MUST be wrapped with `cache_key_wrapper` to guarantee inclusion in the cache key:
> ```sql
> WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'
> ```

#### Vector 3 — SQL injection via Jinja macros

**Scenario:** An attacker injects a `tenant_id` containing SQL in the JWT:
```json
{"tenant_id": "' OR '1'='1"}
```
and attempts to obtain `WHERE tenant_id = '' OR '1'='1'`.

**Architectural countermeasures:**

| Layer | Mechanism | Effectiveness |
|--------|-----------|-----------|
| Regex validation on write in `set_tenant` | `^[a-zA-Z0-9_-]{1,128}$` — rejects quotes, spaces, SQL dashes, etc. | **Eliminates** |
| Server-side JWT validation (ADR-001) | The `tenant_id` is extracted from an HS256-signed JWT. An invalid value is detected before reaching `set_tenant` | **Preventive** |
| `SandboxedEnvironment` Jinja2 | Prevents execution of arbitrary Python code in SQL templates | **Complementary** |
| Read from signed server session | The `tenant_id` in session is signed by `SECRET_KEY` — not forgeable client-side | **Preventive** |

The validation chain is: JWT -> `authenticate` (signature) -> `set_tenant` (regex) ->
server session (HMAC) -> `before_request` (get from session) -> `set_tenant` (regex, again).
Double regex validation eliminates injections even in case of a bug in the JWT layer.

#### Vector 4 — IDOR / Tenant spoofing via client manipulation

**Possible scenarios:**
- Injection of `tenant_id` via URL query param: `?tenant_id=tenant-B`
- Injection via HTTP header: `X-Tenant-ID: tenant-B`
- Client-side session cookie modification
- JWT forgery with a different `tenant_id`

**Architectural countermeasures:**

| Vector | Countermeasure | Effectiveness |
|---------|--------------|-----------|
| URL query param / HTTP header | The `before_request` reads **exclusively** from `flask.session` — never from `request.args`, `request.headers`, or other client inputs | **Eliminates** |
| Cookie modification | Flask cookie signed with HMAC and `SECRET_KEY` 256 bits — forgery detected and rejected | **Eliminates** |
| JWT forgery | JWT signed HS256 with shared secret (ADR-001) — forgery detected | **Eliminates** |
| Expired JWT reuse | `exp` check + anti-replay `jti` (ADR-001) | **Eliminates** |
| Session theft (XSS) | `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True` in production | **Preventive** |

**Fundamental property:** The `tenant_id` is **never** read from a client-controllable
input after SSO session establishment. Its value is:
1. Extracted from the JWT during SSO (validated server-side).
2. Written to the signed server session.
3. Re-read from the server session on each request.
4. Stored in a ContextVar isolated by thread/coroutine.

#### Vector 5 — Security context misalignment during a long request

**Scenario:** A long SQL query is executing. A bug or configuration change modifies the
`tenant_id` value in the ContextVar during this time.

**Analysis:** This scenario is **impossible by construction** in the ContextVar model.

- The ContextVar is thread-local. No other thread can modify another thread's ContextVar.
- Within the same thread (synchronous execution), the ContextVar value can only change
  if code in the same call stack calls `set_tenant()`. The `before_request` calls
  `set_tenant` exactly once, at the start of the request.
- SQLAlchemy SQL query execution is synchronous in the current thread — no interruption
  by another request is possible.
- In Gevent/Eventlet mode, switchpoints only occur at explicit I/O points. Each coroutine
  has its own copy of the Context — the ContextVar value of one coroutine cannot be
  modified by another coroutine.

---

### 2.5 Logging and Audit Policy for Security Events

#### Log segregation principles

Security events related to the tenant context must be emitted to a channel distinct from
standard application logs (`superset.views`, `superset.sql_lab`). This channel is:
`logger = logging.getLogger("superset_auth_kit.security.audit")`.

This segregation enables:
- Filtering only audit events without application noise.
- Routing logs to a SIEM (Splunk, Datadog, ELK) via a distinct Python logging configuration.
- Defining differentiated retention (audit logs: 90 days, application logs: 14 days).

#### Canonical structure of an audit event

Each security audit log must include the following fields in structured JSON format:

```json
{
  "timestamp":      "2026-07-01T23:45:12.891Z",
  "level":          "ERROR",
  "logger":         "superset_auth_kit.security.audit",
  "event":          "TENANT_CONTEXT_MISSING",
  "correlation_id": "req-7f3a8b2c-1234-5678-abcd",
  "sub":            "saas-user-abc12345...",
  "tenant_id":      null,
  "resource":       "POST /api/v1/chart/data",
  "remote_addr":    "192.168.1.10",
  "message":        "Authenticated user without tenant_id in session -- access denied (403)"
}
```

**`correlation_id` field:** Unique identifier of the HTTP request, propagated from a
`X-Request-ID` or `X-Correlation-ID` header if present (APM standard), or generated by
the `before_request` hook (`uuid4()`). This field allows correlating audit logs with
orchestrator logs (Kubernetes, Nginx) and APM traces (OpenTelemetry).

#### Audit events and log levels

| Event | Logger Level | Trigger | OTel Metric |
|-----------|-------------|-------------|-------------|
| `TENANT_SSO_ESTABLISHED` | `INFO` | Successful SSO, session created | `authkit.sso.success` |
| `TENANT_CONTEXT_HYDRATED` | `DEBUG` | `before_request` — tenant re-read from session | (not required) |
| `TENANT_CONTEXT_MISSING` | `ERROR` | Authenticated user, `tenant_id` absent from session | `authkit.tenant.missing` (counter) |
| `TENANT_ID_INVALID` | `CRITICAL` | `TenantResolutionError` raised by `set_tenant` (regex fail) | `authkit.tenant.invalid` (counter) |
| `TENANT_RESIDUAL_DETECTED` | `WARNING` | ContextVar non-empty at start of `before_request` | `authkit.tenant.residual` (counter) |
| `JINJA_TENANT_MISSING` | `CRITICAL` | `TenantResolutionError` from `current_tenant()` | `authkit.jinja.tenant_missing` (counter) |
| `CACHE_KEY_TENANT_ABSENT` | `WARNING` | Detection of a template without `cache_key_wrapper` | `authkit.cache.key_missing` (counter) |

#### OpenTelemetry metrics

```python
# Conceptual instrumentation (not implemented in this ADR)
from opentelemetry import metrics

meter = metrics.get_meter("superset_auth_kit", version="1.0")

# Security incident counters
tenant_missing_counter = meter.create_counter(
    "authkit.tenant.missing",
    description="Authenticated requests without tenant_id in session",
)
tenant_invalid_counter = meter.create_counter(
    "authkit.tenant.invalid",
    description="Attempts with tenant_id failing regex validation",
)
jinja_tenant_missing_counter = meter.create_counter(
    "authkit.jinja.tenant_missing",
    description="SQL templates calling current_tenant() outside authenticated context",
)
sso_success_counter = meter.create_counter(
    "authkit.sso.success",
    description="Successful SSO authentications",
)
```

**Recommended Prometheus / OTel alert:**

```yaml
# Alert rule (Prometheus AlertManager)
- alert: AuthKitTenantContextMissing
  expr: increase(authkit_tenant_missing_total[5m]) > 0
  for: 0m
  severity: critical
  annotations:
    summary: "Tenant isolation incident -- unauthenticated context access detected"
    description: "{{ $value }} requests without tenant_id in the last 5 minutes."
```

---

### 3.3 Future Extension Strategy — Async Tasks (Celery)

*(Out-of-Scope for v1 — documented for the roadmap)*

Celery tasks (scheduled email alerts, async exports, thumbnail generation) execute
**outside the HTTP request context**. The ContextVar is not automatically propagated
to Celery workers.

**Future rehydration strategy:**

1. **At task creation:** The `tenant_id` is passed as an explicit argument:
   ```python
   send_report_email.delay(
       report_id=42,
       tenant_id=TenantContext.get_tenant(),  # explicit copy
   )
   ```

2. **In the Celery worker:** A `@task_prerun` hook rehydrates the context:
   ```python
   @task_prerun.connect
   def hydrate_tenant_for_task(task_id, task, kwargs, **extra):
       if "tenant_id" in kwargs:
           token = TenantContext.set_tenant(kwargs["tenant_id"])
           task._sak_token = token

   @task_postrun.connect
   def cleanup_tenant_for_task(task, **extra):
       token = getattr(task, "_sak_token", None)
       if token:
           TenantContext.reset(token)
   ```

3. **Validation:** The `tenant_id` passed as argument is re-validated by `set_tenant()`
   (regex validation) — no bypass possible via the message queue.

4. **Celery queue isolation:** In high-isolation multi-tenant production environments,
   dedicated Celery queues per tenant can be used to avoid any resource sharing
   (DB connections, worker memory) between tenants.

---

## Section 3 — Decision Summary (ADR Submission)

---

### ADR-301: Client Context Propagation and Thread-Safety Mechanism

**Title**: Tenant_id propagation via `contextvars.ContextVar` (PEP 567)

**Context**

Propagating tenant context in a multi-worker Gunicorn architecture (sync, gthread,
gevent modes) requires a mechanism guaranteeing total isolation between concurrent
requests on the same process. Four mechanisms were evaluated:
`flask.g`, `threading.local`, `contextvars.ContextVar`, and the Flask session cookie.

**Decision**

The chosen mechanism is `contextvars.ContextVar` (PEP 567, Python 3.7+), named
`authkit_tenant_id`, with default value `None`:

```python
_tenant_ctx: ContextVar[Optional[str]] = ContextVar("authkit_tenant_id", default=None)
```

This ContextVar is unique at module level in `superset_auth_kit.tenant.context`.
The exposed public API is the static class `TenantContext`:
- `TenantContext.set_tenant(tenant_id: str) -> Token` — validates and writes
- `TenantContext.get_tenant() -> str` — reads or raises `TenantResolutionError`
- `TenantContext.get_tenant_or_none() -> str | None` — read without exception
- `TenantContext.reset(token: Token) -> None` — deterministic restoration
- `TenantContext.clear() -> None` — set to None (safety net)

**Justification**

- **Gevent/Eventlet isolation:** `ContextVar` is compatible with Gevent monkey-patching
  (greenlet 0.4.17+). `threading.local` is not — risk of cross-request contamination.
- **Deterministic restoration:** The pattern `token = ctx.set(v)` / `ctx.reset(token)`
  restores exactly the previous state, including `None`. No other mechanism provides this.
- **Testability:** `contextvars.copy_context().run(fn)` allows isolating contexts in
  unit tests without Flask fixtures or mocks.
- **Alignment with Flask 2.3:** Flask 2.3 itself uses ContextVars for its internal
  proxies. SAK aligns with this architecture rather than introducing a heterogeneous
  mechanism.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| `flask.g` | Bound to AppContext, not RequestContext. Possible sharing between requests. No restoration token. |
| `threading.local` | Not Gevent/Eventlet compatible. No restoration token. |
| Session Cookie | Readable client-side. Violates server-side immutability. |

**Consequences**

- Positive: Proven thread-safety, testability without Flask, compatibility with all workers.
- Negative: Celery tasks must explicitly pass `tenant_id` as an argument (future — §3.3).
- Mitigation: Celery rehydration pattern documented and tooled (§3.3).

---

### ADR-302: Context Lifecycle and Cleanup Protocol

**Title**: Double before_request/teardown_request safety net with deterministic `reset(token)`

**Context**

The `authkit_tenant_id` ContextVar must be initialized at the start of each HTTP request
and cleaned up at its end, **even on exception**. The cleanup must be deterministic and
robust to edge cases (Python exceptions, Flask `abort()`, timeouts).

**Decision**

Two hooks are registered on the main Flask application (not only on the SSO Blueprint):

**Hook 1 — `before_request` (hydration):**
For each request from an authenticated user (Flask-Login), read `tenant_id` from
`flask.session["_sak_tenant"]`, validate via `TenantContext.set_tenant()`, store the
token in `flask.g._sak_tenant_token`.

**Hook 2 — `teardown_request` (cleanup):**
Read `g._sak_tenant_token` and call `TenantContext.reset(token)` if present,
`TenantContext.clear()` otherwise. Executed by Flask in all scenarios except
SIGKILL/hard crash.

**Session write during SSO:** In `authenticate_sso()`, after JWT validation:
```python
session["_sak_tenant"] = identity.tenant_id
```
The session is HMAC-signed (`SECRET_KEY`) — the `tenant_id` is not forgeable client-side.

**Justification**

- **Flask guarantee:** `teardown_request` is executed via `RequestContext.pop()` which
  uses `try/finally`. Guaranteed for any Python exception, `abort()`, SQLAlchemy timeout.
- **Double safety net:** Even if `teardown_request` fails (hard crash), the next
  `before_request` reinitializes the ContextVar.
- **Residue detectable:** If `get_tenant_or_none()` returns a non-None value at the start
  of `before_request`, this is an anomaly logged as `TENANT_RESIDUAL_DETECTED`.
- **`reset(token)` vs `clear()`:** `reset(token)` restores the exact previous state
  (initial None), whereas `clear()` forces None without knowledge of the previous state.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| Cleanup only in SSO Blueprint teardown | The tenant context must be available for all requests, not only SSO. |
| `atexit` or signal handlers | Not triggered at the end of each request — triggered at process end. |
| `ctx.set(None)` only (without reset) | Does not restore the previous state — risk if the previous value was not None. |

**Consequences**

- Positive: Cleanup guaranteed for 99.99%+ of cases. Double safety net. Residue detection log.
- Negative: Global `before_request` hook slightly slower for each request. Cost < 0.5ms.
- Mitigation: Use `get_tenant_or_none()` without exception for public endpoints.

---

### ADR-303: Immutability and Sovereignty of the Tenant Source of Truth

**Title**: The tenant_id is immutable, extracted exclusively from the JWT, persisted in
a signed server session

**Context**

The `tenant_id` is a critical security attribute determining data isolation between SaaS
clients. Its value must be deterministic, verifiable, and not influenceable by the client
after session establishment.

**Decision**

The sovereignty chain is:

```
Signed JWT (HS256, shared secret Next.js <-> SAK)
  -> authenticate() [ADR-001]: signature + exp + iat + jti verification
  -> identity.tenant_id
    -> session["_sak_tenant"] = tenant_id  (Flask session signed HMAC)
      -> before_request: session.get("_sak_tenant")
        -> TenantContext.set_tenant(tenant_id)  (regex validation)
          -> ContextVar authkit_tenant_id
```

**Immutability rules:**
1. The `tenant_id` **can never** be read from `request.args`, `request.form`,
   `request.json`, `request.headers`, or any other client-controllable input.
2. The `tenant_id` **can never** be modified after being written to the session
   (the session is only re-written during a new SSO flow with a new JWT).
3. Regex validation (`^[a-zA-Z0-9_-]{1,128}$`) is applied **at each write**
   to the ContextVar (including rehydration from session).

**Justification**

- **Single source**: JWT (Next.js side) -> SAK (Superset side). Zero intermediate
  injection point.
- **Non-forgeable**: The JWT is HS256-signed, the session is HMAC-signed.
- **Defense in depth**: Regex validation in `set_tenant()` is the last safety net.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| HTTP header `X-Tenant-ID` | Forgeable by the client. Bypassable via proxy. |
| Query param `?tenant=...` | Forgeable and logged in clear text in access logs. |
| Rehydration from FAB identity (user.extra_json) | The `extra_json` is mutable from the Superset admin UI — injection possible by a Superset administrator. |

**Consequences**

- Positive: Cryptographically guaranteed isolation. Not bypassable without the JWT secret.
- Negative: Rotating the `tenant_id` requires a full new SSO flow (new JWT). This is a
  desired property, not a limitation.

---

### ADR-304: Jinja Macro Integration and SQL Execution Security

**Title**: Pure, Fail Closed `current_tenant()` via `JINJA_CONTEXT_ADDONS` +
mandatory `cache_key_wrapper`

**Context**

Superset RLS SQL templates use Jinja2 to inject dynamic values into WHERE clauses.
The `tenant_id` must be accessible in these templates, protected against SQL injection,
and trigger a blocking error in case of missing context.

**Decision**

**Exposure:**
```python
JINJA_CONTEXT_ADDONS = {"current_tenant": TenantContext.get_tenant}
```

**Mandatory usage in SQL templates:**
```sql
WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'
```

**Guaranteed properties of `current_tenant()`:**
- Read-only (no state mutation)
- Regex validation on write (no SQL injection possible)
- `TenantResolutionError` if context absent (Fail Closed — never returns `None`)
- O(1) CPU — `ContextVar.get()` is a C-level operation

**Prohibition on returning `None`:** A `None` in `WHERE tenant_id = '{{ current_tenant() }}'`
generates either `WHERE tenant_id = 'None'` (no filtering), or `WHERE tenant_id = NULL`
(zero rows or full scan). Both are isolation violations. The exception is the only correct
response.

**Justification**

- **Fail Closed**: An exception in Jinja stops SQL template execution. No query is
  executed without a tenant filter.
- **Mandatory `cache_key_wrapper`**: Without it, the `tenant_id` is in the SQL but
  absent from the cache key -> cross-tenant collision in `data_cache`.
- **`SandboxedEnvironment`**: Jinja2 Sandbox prevents access to sensitive Python
  attributes in templates.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| Return `""` (empty string) if absent | `WHERE tenant_id = ''` filters nothing. Isolation violation. |
| Return `"__NO_TENANT__"` if absent | Same problem — the WHERE clause would be false but non-blocking. |
| Inject tenant directly via FAB RLS (UI) | Possible but static — does not support dynamic tenants (UUID). |

**Consequences**

- Positive: SQL isolation guaranteed by construction. SQL injection impossible.
- Negative: SQL template developers must use `cache_key_wrapper(current_tenant())`.
- Technical debt: `context_addons()` with `@lru_cache` is Superset internal. Monitor
  between versions (§2.3).

---

### ADR-305: Cache-Agnostic Key Partitioning Algorithm

**Title**: Partitioning via `cache_key_wrapper(current_tenant())` in `data_cache`;
`thumbnail_cache` disabled pending patch

**Decision**

| Layer | Partitioning strategy | Status |
|--------|------------------------------|--------|
| `data_cache` | `{{ cache_key_wrapper(current_tenant()) }}` in SQL template | ✅ Covered |
| `filter_state_cache` | UUID per session — no collision possible | ✅ Native |
| `explore_form_data_cache` | `form_data` naturally distinct per tenant + chart | ✅ Acceptable |
| `cache` (general) | Non-tenant-specific data for current bundles | ✅ Not required |
| `thumbnail_cache` | **DISABLED** in multi-tenant (`THUMBNAIL_CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}`) | ⚠️ Technical debt |

**Algorithm for `data_cache`:** Superset's `hash_from_dict` (SHA-256) applied on a dict
including `extra_cache_keys: [tenant_id]`. SHA-256 collision-resistance guarantees
`H(..., "tenant-A") != H(..., "tenant-B")` for all `tenant-A != tenant-B`.

**Technical debt — `thumbnail_cache`:** The `DashboardScreenshot.digest` is computed
without the tenant. Overriding requires modifying `superset/utils/screenshots.py`
(internal API). Deferred to SAK v2 roadmap. In v1, `thumbnail_cache` is disabled.

**Consequences**

- Positive: `data_cache` isolation guaranteed. Zero public Superset API modification.
- Negative: Thumbnails disabled in v1.
- Debt mitigation: v2 roadmap: patch `DashboardScreenshot.digest` with tenant token.

---

### ADR-306: Global Failure Policy ("Fail Closed") and Audit Metrics

**Title**: Fail Closed on any absent/invalid tenant context + dedicated audit log
`superset_auth_kit.security.audit` + OpenTelemetry metrics

**Decision**

**Fail Closed policy:**

| Condition | SAK response | HTTP code | Log level | Metric |
|-----------|-------------|-----------|-----------|--------|
| Authenticated user + `tenant_id` absent from session | `abort(403)` | 403 | `ERROR` | `authkit.tenant.missing` |
| `set_tenant()`: invalid regex | `TenantResolutionError` -> 500 | 500 | `CRITICAL` | `authkit.tenant.invalid` |
| `get_tenant()` outside context (None) | `TenantResolutionError` -> SQL blocked | 500 | `CRITICAL` | `authkit.jinja.tenant_missing` |
| Residual ContextVar detected | Log + reinitialization | — | `WARNING` | `authkit.tenant.residual` |

**No fallback value is ever returned** for a security attribute.

**Dedicated Audit Log:** Logger: `superset_auth_kit.security.audit`. Format: Structured
JSON with fields `timestamp`, `level`, `event`, `correlation_id`, `sub`, `tenant_id`,
`resource`, `remote_addr`, `message`.

**OpenTelemetry Metrics:** Four counters (`authkit.sso.success`, `authkit.tenant.missing`,
`authkit.tenant.invalid`, `authkit.jinja.tenant_missing`) + one gauge
(`authkit.tenant.residual`).

**Prometheus alert:** `authkit_tenant_missing_total > 0` within a 5-minute window
-> `severity: critical`.

**Justification**

- **Fail Closed vs Fail Open:** An unfiltered access (fail open) exposes all data from
  all tenants. An access denial (fail closed) exposes no data.
- **Separate audit:** A SIEM or Prometheus alerting can only correlate incidents if
  security events are in a distinct channel with a predictable structure.
- **Metrics vs Logs:** Metrics enable real-time alerts. Logs enable post-incident
  forensics. Both are necessary.

**Rejected alternatives**

| Alternative | Reason for rejection |
|-------------|-----------------|
| Return `"__MISSING__"` for cases without tenant | Creates a sentinel value that could pass through poorly written filters. Disguised Fail Open. |
| Log only without blocking | The incident is detected but the request continues without a tenant filter — isolation violation. |
| Metrics in application logs | Hard to aggregate and alert on. Text logs are not counters. |

**Consequences**

- Positive: Every tenant isolation violation is detected, blocked, and alerted in real time.
  Zero data exposed on failure.
- Negative: A misconfigured user (without `tenant_id` in JWT) gets a 403 without an
  explicit visible message. Mitigation: `X-AuthKit-Error: tenant_context_missing` header.
- Operational note: The first trigger of `authkit.tenant.missing` in production must
  trigger an immediate review of audit logs to distinguish a configuration bug from
  an attack attempt.

---

*End of document ADR-003 — superset-auth-kit Multi-Tenant Context and Authorization Engine*
