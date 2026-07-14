"""ADR-305 Phase 2: Multi-tenant cache partitioning and isolation policies.

Three security properties verified formally:

P1 — cache_key_wrapper CONTRACT
    ``cache_key_wrapper(current_tenant())`` adds the tenant_id to
    ``extra_cache_keys``, forcing its inclusion in the SHA-256 hash of the
    final cache key. Property verified via real Jinja rendering (jinja2 installed).

P2 — PER-TENANT DETERMINISM
    Two distinct tenants on the same analytical resource → strictly different cache
    keys (key_A != key_B).
    Corollary: same resource, same tenant → stable key (key_A1 == key_A2).

P3 — ISOLATION (no-collision)
    A value written to the cache under Tenant A's key produces a deterministic
    cache miss for Tenant B accessing the same resource.

Required Jinja pattern in all multi-tenant SQL templates:

    WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'

Test architecture (no Superset dependency):
    _ExtraCacheStub   → replicates the superset.jinja_context.ExtraCache contract
    _render_sql()     → real Jinja2 rendering with current_tenant + cache_key_wrapper
    _compute_cache_key() → SHA-256 mirror of Superset's QueryObject.cache_key()
    dict              → in-memory cache backend (simulates Redis / Flask-Caching)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import jinja2
import pytest

from superset_auth_kit.tenant.context import TenantContext

# ── Reference SQL template ────────────────────────────────────────────────────
# Template used across all test classes to represent a real analytical report.
# The tenant value is both inserted in the WHERE clause (data isolation)
# and captured by cache_key_wrapper (cache isolation).

_SQL_TEMPLATE = (
    "SELECT event_date, SUM(metric_value) AS total\n"
    "FROM analytics_events\n"
    "WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'\n"
    "  AND event_date >= '2024-01-01'\n"
    "GROUP BY event_date"
)


# ─────────────────────────────────────────────────────────────────────────────
# Test infrastructure — stubs with no Superset dependency
# ─────────────────────────────────────────────────────────────────────────────


class _ExtraCacheStub:
    """Stub for Superset's ``ExtraCache`` contract (superset/jinja_context.py).

    Superset automatically injects ``cache_key_wrapper`` into the Jinja context
    of each SQL template. This method is bound to an ``ExtraCache`` instance
    that maintains the ``extra_cache_keys`` list — included in the final digest.

    This stub replicates EXACTLY that behavior for unit tests:
    - ``cache_key_wrapper(value)`` → appends *value* to ``extra_cache_keys``,
      returns *value* transparently (the value is inserted into the SQL).
    - ``extra_cache_keys`` → cumulative list of values submitted to the hash.
    """

    def __init__(self) -> None:
        self.extra_cache_keys: list[Any] = []

    def cache_key_wrapper(self, value: Any) -> Any:
        """Capture *value* for the hash and return it unchanged."""
        self.extra_cache_keys.append(value)
        return value


def _render_sql(sql_template: str, tenant_id: str, extra_cache: _ExtraCacheStub) -> str:
    """Render a Jinja2 SQL template with the tenant context + ExtraCache stub.

    Reproduces the exact sequence of the Superset template engine:
    1. ``current_tenant`` is resolved from the ContextVar (hydrated by before_request).
    2. ``cache_key_wrapper`` is provided by the current ExtraCache instance.
    3. The template is rendered — the value is both inserted into the SQL AND recorded.

    Args:
        sql_template: Jinja2 SQL template (e.g. ``_SQL_TEMPLATE``).
        tenant_id: Tenant to activate in the ContextVar for this render.
        extra_cache: ExtraCache stub that will capture the tenant value.

    Returns:
        SQL rendered with the tenant value substituted in.
    """
    token = TenantContext.set_tenant(tenant_id)
    try:
        env = jinja2.Environment(autoescape=False)
        tpl = env.from_string(sql_template)
        return tpl.render(
            current_tenant=TenantContext.get_tenant,
            cache_key_wrapper=extra_cache.cache_key_wrapper,
        )
    finally:
        TenantContext.reset(token)


def _compute_cache_key(base_query: str, extra_cache_keys: list[Any]) -> str:
    """Compute a SHA-256 cache key including extra_cache_keys.

    Simplified mirror of ``QueryObject.cache_key()`` in Superset
    (superset/connectors/sqla/models.py). The key property:
    ``extra_cache_keys`` is included in the digest — any difference in
    ``extra_cache_keys`` produces a different key, even if the other
    query parameters (metrics, filters, etc.) are identical.

    Args:
        base_query: SQL template (represents the QueryObject parameters).
        extra_cache_keys: Values captured by ``cache_key_wrapper``.

    Returns:
        SHA-256 hex digest (64 characters).
    """
    key_dict: dict[str, Any] = {
        "query": base_query,
        "extra_cache_keys": sorted(str(k) for k in extra_cache_keys),
    }
    return hashlib.sha256(
        json.dumps(key_dict, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# P1 — ExtraCache contract: cache_key_wrapper captures the tenant_id
# ─────────────────────────────────────────────────────────────────────────────


class TestExtraCacheContract:
    """Verify that cache_key_wrapper(current_tenant()) correctly intercepts
    the ContextVar value and deposits it in extra_cache_keys."""

    def test_cache_key_wrapper_appends_tenant_to_extra_cache_keys(self) -> None:
        """cache_key_wrapper receives the ContextVar value and adds it to extra_cache_keys."""
        extra = _ExtraCacheStub()
        assert extra.extra_cache_keys == []

        token = TenantContext.set_tenant("tenant-contract-test")
        try:
            returned = extra.cache_key_wrapper(TenantContext.get_tenant())
        finally:
            TenantContext.reset(token)

        assert returned == "tenant-contract-test", (
            "cache_key_wrapper must return the value transparently "
            "(so it is inserted into the SQL WHERE clause)"
        )
        assert extra.extra_cache_keys == ["tenant-contract-test"], (
            "cache_key_wrapper must have added tenant_id to extra_cache_keys "
            "(for its inclusion in the SHA-256 hash of the cache key)"
        )

    def test_jinja_rendering_populates_extra_cache_keys(self) -> None:
        """Jinja2 rendering of '{{ cache_key_wrapper(current_tenant()) }}' hydrates extra_cache_keys."""
        extra = _ExtraCacheStub()
        rendered = _render_sql(_SQL_TEMPLATE, "tenant-jinja-test", extra)

        # 1. The value is correctly inserted into the rendered SQL
        assert "tenant-jinja-test" in rendered, (
            "The tenant value must appear in the rendered SQL "
            "(successful Jinja substitution)"
        )
        assert "{{ cache_key_wrapper" not in rendered, (
            "The Jinja template must be fully rendered — no residual tags"
        )

        # 2. The value is also captured in extra_cache_keys
        assert extra.extra_cache_keys == ["tenant-jinja-test"], (
            "Jinja rendering must have called cache_key_wrapper and deposited "
            "tenant_id in extra_cache_keys"
        )

    def test_cache_key_wrapper_returns_value_transparent(self) -> None:
        """cache_key_wrapper returns exactly the value received (pass-through for the SQL)."""
        extra = _ExtraCacheStub()
        token = TenantContext.set_tenant("tenant-passthrough")
        try:
            tenant_val = TenantContext.get_tenant()
            result = extra.cache_key_wrapper(tenant_val)
        finally:
            TenantContext.reset(token)

        assert result is tenant_val, (
            "cache_key_wrapper must return the SAME reference (not a copy) "
            "to guarantee that the SQL receives exactly the validated tenant value"
        )

    def test_multiple_calls_accumulate_in_extra_cache_keys(self) -> None:
        """Multiple calls to cache_key_wrapper accumulate all values."""
        extra = _ExtraCacheStub()
        token_a = TenantContext.set_tenant("tenant-multi-A")
        extra.cache_key_wrapper(TenantContext.get_tenant())
        TenantContext.reset(token_a)

        token_b = TenantContext.set_tenant("tenant-multi-B")
        extra.cache_key_wrapper(TenantContext.get_tenant())
        TenantContext.reset(token_b)

        assert extra.extra_cache_keys == ["tenant-multi-A", "tenant-multi-B"]

    def test_without_cache_key_wrapper_extra_cache_keys_stays_empty(self) -> None:
        """Without cache_key_wrapper, extra_cache_keys stays empty — demonstrating the risk.

        If the SQL template uses only {{ current_tenant() }} without
        cache_key_wrapper(), the SQL is correct BUT extra_cache_keys is empty.
        Two tenants would then get THE SAME cache key (collision).
        This test formally demonstrates WHY cache_key_wrapper is required.
        """
        extra = _ExtraCacheStub()

        # INCORRECT template: current_tenant() without cache_key_wrapper
        sql_without_wrapper = "SELECT * FROM t WHERE tenant_id = '{{ current_tenant() }}'"
        env = jinja2.Environment(autoescape=False)
        tpl = env.from_string(sql_without_wrapper)

        token = TenantContext.set_tenant("tenant-no-wrapper")
        try:
            rendered = tpl.render(
                current_tenant=TenantContext.get_tenant,
                # cache_key_wrapper available but not used in this template
                cache_key_wrapper=extra.cache_key_wrapper,
            )
        finally:
            TenantContext.reset(token)

        assert "tenant-no-wrapper" in rendered, "The SQL is correct (data filtered)"
        assert extra.extra_cache_keys == [], (
            "WITHOUT cache_key_wrapper, extra_cache_keys is empty — "
            "the cache key does NOT contain the tenant_id -> collision risk"
        )


# ─────────────────────────────────────────────────────────────────────────────
# P2 — Determinism: same QueryContext, different tenants → different keys
# ─────────────────────────────────────────────────────────────────────────────


class TestCacheKeyDeterminism:
    """Verify that two tenants on the same analytical resource produce
    strictly different cache keys (P2 — ADR-305 §3.1)."""

    def test_cache_key_determinism_per_tenant(self) -> None:
        """Same QueryContext, two distinct tenants → different cache keys.

        Scenario: the 'Monthly Metrics' dashboard is displayed simultaneously
        by two SaaS customers (Tenant A = 'acme-corp', Tenant B = 'globex-inc').
        Same datasource, same metrics, same period → only the tenant differs.
        Cache keys MUST diverge to prevent Superset from serving to
        Globex the data cached for Acme.
        """
        # ── Simulate rendering for Tenant A ──────────────────────────────────
        extra_a = _ExtraCacheStub()
        rendered_sql_a = _render_sql(_SQL_TEMPLATE, "acme-corp", extra_a)
        key_a = _compute_cache_key(_SQL_TEMPLATE, extra_a.extra_cache_keys)

        # ── Simulate rendering for Tenant B ──────────────────────────────────
        extra_b = _ExtraCacheStub()
        rendered_sql_b = _render_sql(_SQL_TEMPLATE, "globex-inc", extra_b)
        key_b = _compute_cache_key(_SQL_TEMPLATE, extra_b.extra_cache_keys)

        # ── Security assertions ───────────────────────────────────────────────
        assert extra_a.extra_cache_keys == ["acme-corp"], (
            "Tenant A must have deposited 'acme-corp' in extra_cache_keys"
        )
        assert extra_b.extra_cache_keys == ["globex-inc"], (
            "Tenant B must have deposited 'globex-inc' in extra_cache_keys"
        )
        assert "acme-corp" in rendered_sql_a, "SQL for A must filter on acme-corp"
        assert "globex-inc" in rendered_sql_b, "SQL for B must filter on globex-inc"
        assert key_a != key_b, (
            f"KEY COLLISION DETECTED: Tenant A and Tenant B share the same "
            f"cache key ({key_a[:16]}...). cache_key_wrapper did not produce "
            f"divergence — verify that extra_cache_keys is included in the hash."
        )

    def test_same_tenant_same_query_produces_stable_key(self) -> None:
        """Same tenant, same query, two successive renders → identical key (cache hit).

        Determinism property: the cache key must be stable between two renders
        of the same template for the same tenant. If the key changed on each
        render, the cache would be completely ineffective (hit rate = 0%).
        """
        extra_1 = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "stable-tenant", extra_1)
        key_1 = _compute_cache_key(_SQL_TEMPLATE, extra_1.extra_cache_keys)

        extra_2 = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "stable-tenant", extra_2)
        key_2 = _compute_cache_key(_SQL_TEMPLATE, extra_2.extra_cache_keys)

        assert key_1 == key_2, (
            "The cache key for the same tenant must be stable across renders "
            f"({key_1[:16]}... != {key_2[:16]}...) — determinism regression detected"
        )

    def test_n_tenants_produce_n_distinct_cache_keys(self) -> None:
        """N distinct tenants → N all-different cache keys (injective property).

        Verifies that there are no hash collisions between tenants even with
        a large number of simultaneous SaaS customers.
        """
        n = 20
        tenants = [f"tenant-saas-{i:03d}" for i in range(n)]
        cache_keys: list[str] = []

        for tenant_id in tenants:
            extra = _ExtraCacheStub()
            _render_sql(_SQL_TEMPLATE, tenant_id, extra)
            key = _compute_cache_key(_SQL_TEMPLATE, extra.extra_cache_keys)
            cache_keys.append(key)

        # All keys must be distinct
        assert len(set(cache_keys)) == n, (
            f"COLLISION DETECTED among {n} tenants: "
            f"{n - len(set(cache_keys))} collision(s). "
            f"The hash must produce distinct keys for each tenant."
        )

    def test_key_without_cache_key_wrapper_collides_across_tenants(self) -> None:
        """ANTI-PATTERN demonstrated: without cache_key_wrapper, keys collide.

        If the template omits cache_key_wrapper, extra_cache_keys is always empty
        → _compute_cache_key produces the same digest for A and B → guaranteed collision.
        This test formally documents the risk to justify the required pattern.
        """
        # Incorrect template — WITHOUT cache_key_wrapper
        sql_without_wrapper = (
            "SELECT metric_value FROM analytics_events\n"
            "WHERE tenant_id = '{{ current_tenant() }}'"
        )

        extra_a = _ExtraCacheStub()
        rendered_a = _render_sql(sql_without_wrapper, "tenant-X", extra_a)
        # extra_cache_keys empty — use the rendered SQL as base key anyway
        key_a_broken = _compute_cache_key(sql_without_wrapper, extra_a.extra_cache_keys)

        extra_b = _ExtraCacheStub()
        rendered_b = _render_sql(sql_without_wrapper, "tenant-Y", extra_b)
        key_b_broken = _compute_cache_key(sql_without_wrapper, extra_b.extra_cache_keys)

        # The rendered SQLs differ (WHERE clause filters correctly)
        assert rendered_a != rendered_b, "Rendered SQLs must differ (different tenants)"

        # BUT cache keys collide because extra_cache_keys is empty for both
        assert extra_a.extra_cache_keys == []
        assert extra_b.extra_cache_keys == []
        assert key_a_broken == key_b_broken, (
            "This test validates the DANGEROUS behavior: without cache_key_wrapper, "
            "cache keys are identical even for different tenants. "
            "Note: in Superset, the rendered SQL is NOT included in cache_key() — "
            "only the QueryObject parameters and extra_cache_keys are."
        )


# ─────────────────────────────────────────────────────────────────────────────
# P3 — Isolation: Tenant A's data is not accessible to Tenant B
# ─────────────────────────────────────────────────────────────────────────────


class TestCacheLeakPrevention:
    """Verify that the data cache is isolated between tenants (P3 — ADR-305 §3.2).

    Simulates Flask-Caching / Redis with an in-memory dict. The partitioning
    principle is identical regardless of the backend (SimpleCache, Redis,
    Memcached): the KEY is different so entries are physically separate.
    """

    def test_cache_leak_prevention(self) -> None:
        """Tenant A writes to the cache → Tenant B gets a deterministic cache miss.

        Scenario: 'acme-corp' loads its dashboard → Superset executes the SQL,
        caches the result (key_A). 'globex-inc' loads the same dashboard →
        Superset looks up the cache with key_B != key_A → cache miss → new
        SQL execution (Acme's data is NEVER served to Globex).
        """
        cache_store: dict[str, Any] = {}  # simulates Redis / Flask-Caching

        # ── Tenant A fills the cache ──────────────────────────────────────────
        extra_a = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "acme-corp", extra_a)
        key_a = _compute_cache_key(_SQL_TEMPLATE, extra_a.extra_cache_keys)
        cache_store[key_a] = {
            "rows": [
                {"event_date": "2024-01-01", "total": 9_999},
                {"event_date": "2024-01-02", "total": 8_888},
            ],
            "tenant": "acme-corp",
            "cache_hit": True,
        }

        # ── Tenant B attempts to read the same analytical resource ────────────
        extra_b = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "globex-inc", extra_b)
        key_b = _compute_cache_key(_SQL_TEMPLATE, extra_b.extra_cache_keys)

        result_for_b = cache_store.get(key_b)

        # ── Security assertions ───────────────────────────────────────────────
        assert key_a != key_b, (
            "Pre-condition: cache keys must diverge for the test to be meaningful"
        )
        assert result_for_b is None, (
            f"CACHE LEAK DETECTED: Tenant B ('globex-inc') retrieved "
            f"Tenant A's ('acme-corp') data via key {key_b[:16]}...\n"
            f"key_A={key_a[:16]}..., key_B={key_b[:16]}...\n"
            f"Result obtained by B: {result_for_b}"
        )

    def test_tenant_a_data_remains_accessible_after_tenant_b_read(self) -> None:
        """Tenant A's data is not corrupted by Tenant B's read."""
        cache_store: dict[str, Any] = {}
        acme_data = {"rows": [{"total": 42}], "tenant": "acme"}

        # Tenant A writes
        extra_a = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "acme-corp", extra_a)
        key_a = _compute_cache_key(_SQL_TEMPLATE, extra_a.extra_cache_keys)
        cache_store[key_a] = acme_data

        # Tenant B reads (cache miss)
        extra_b = _ExtraCacheStub()
        _render_sql(_SQL_TEMPLATE, "globex-inc", extra_b)
        key_b = _compute_cache_key(_SQL_TEMPLATE, extra_b.extra_cache_keys)
        cache_store.get(key_b)  # miss — ignore the result

        # Tenant A can still read its own data
        result_a_after = cache_store.get(key_a)
        assert result_a_after is acme_data, (
            "Tenant A's data must not be altered by B's read"
        )
        assert result_a_after["rows"][0]["total"] == 42

    def test_separate_write_per_tenant_no_overwrite(self) -> None:
        """Two tenants write to the cache → separate data, no overwrite."""
        cache_store: dict[str, Any] = {}

        for tenant_id, value in [("acme-corp", 100), ("globex-inc", 200)]:
            extra = _ExtraCacheStub()
            _render_sql(_SQL_TEMPLATE, tenant_id, extra)
            key = _compute_cache_key(_SQL_TEMPLATE, extra.extra_cache_keys)
            cache_store[key] = {"total": value, "tenant": tenant_id}

        # Read each tenant's data
        for tenant_id, expected_value in [("acme-corp", 100), ("globex-inc", 200)]:
            extra = _ExtraCacheStub()
            _render_sql(_SQL_TEMPLATE, tenant_id, extra)
            key = _compute_cache_key(_SQL_TEMPLATE, extra.extra_cache_keys)
            result = cache_store.get(key)

            assert result is not None, f"Unexpected cache miss for {tenant_id}"
            assert result["total"] == expected_value, (
                f"Tenant {tenant_id} read {result['total']!r} instead of {expected_value}"
            )
            assert result["tenant"] == tenant_id, (
                f"Tenant {tenant_id} retrieved another tenant's data: "
                f"{result['tenant']!r}"
            )

    def test_cache_miss_forces_fresh_sql_execution(self) -> None:
        """Cache miss for Tenant B → simulating a fresh SQL execution.

        In production, a cache miss triggers SQL execution via Superset.
        This test models that decision: if cache.get(key_B) is None, the system
        MUST execute the SQL for B (with its own WHERE tenant_id='B' filter).
        """
        cache_store: dict[str, Any] = {}
        sql_executions: list[str] = []  # journal of simulated SQL executions

        def _execute_sql_for_tenant(tenant_id: str) -> dict[str, Any]:
            """Simulate Superset SQL execution for a given tenant."""
            sql_executions.append(f"EXECUTED SQL FOR {tenant_id}")
            return {"rows": [{"result": f"fresh-data-for-{tenant_id}"}]}

        def _get_or_execute(tenant_id: str) -> dict[str, Any]:
            """Simulate Superset's cache-aside pattern."""
            extra = _ExtraCacheStub()
            _render_sql(_SQL_TEMPLATE, tenant_id, extra)
            key = _compute_cache_key(_SQL_TEMPLATE, extra.extra_cache_keys)

            cached = cache_store.get(key)
            if cached is not None:
                return cached

            # Cache miss → SQL execution
            result = _execute_sql_for_tenant(tenant_id)
            cache_store[key] = result
            return result

        # Tenant A: first access → SQL executed, result cached
        result_a1 = _get_or_execute("acme-corp")
        assert len(sql_executions) == 1, "First A access → 1 SQL execution"

        # Tenant A: second access → cache hit, no new SQL execution
        result_a2 = _get_or_execute("acme-corp")
        assert len(sql_executions) == 1, "Second A access → cache hit, 0 new executions"
        assert result_a1 is result_a2, "Cache hit must return the same reference"

        # Tenant B: first access → cache miss (key B != key A) → SQL executed
        result_b = _get_or_execute("globex-inc")
        assert len(sql_executions) == 2, (
            "First B access → cache miss (A's data not served) → 1 new SQL execution"
        )
        assert "globex-inc" in result_b["rows"][0]["result"], (
            "B must receive its own fresh data, not A's"
        )
        assert "acme-corp" not in result_b["rows"][0]["result"]
