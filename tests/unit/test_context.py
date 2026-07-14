"""Unit tests — TenantContext (ContextVar, thread isolation, sanitization)."""

from __future__ import annotations

import contextvars
import threading
import time

import pytest

from superset_auth_kit.exceptions import TenantContextMissingError, TenantResolutionError
from superset_auth_kit.tenant.context import TenantContext


# ── Helpers ──────────────────────────────────────────────────────────────────


def _clean() -> None:
    """Reset the context between tests."""
    TenantContext.clear()


# ── set_tenant / get_tenant ───────────────────────────────────────────────────


def test_set_and_get_nominal() -> None:
    _clean()
    TenantContext.set_tenant("tenant-abc")
    assert TenantContext.get_tenant() == "tenant-abc"
    _clean()


def test_get_without_set_raises() -> None:
    """get_tenant() without context raises TenantContextMissingError (subclass of TenantResolutionError)."""
    _clean()
    # TenantContextMissingError IS a TenantResolutionError — both assertions pass.
    with pytest.raises(TenantContextMissingError):
        TenantContext.get_tenant()


def test_get_without_set_is_subclass_of_resolution_error() -> None:
    """TenantContextMissingError is catchable via except TenantResolutionError (hierarchy)."""
    _clean()
    with pytest.raises(TenantResolutionError):  # subclass caught
        TenantContext.get_tenant()


def test_get_tenant_or_none_without_set_returns_none() -> None:
    _clean()
    assert TenantContext.get_tenant_or_none() is None


def test_get_tenant_or_none_after_set() -> None:
    _clean()
    TenantContext.set_tenant("tenant-xyz")
    assert TenantContext.get_tenant_or_none() == "tenant-xyz"
    _clean()


# ── tenant_id format validation ───────────────────────────────────────────────


@pytest.mark.parametrize("invalid", [
    "",                  # empty
    " ",                 # space only
    "invalid tenant",    # space in identifier
    "tenant!",           # forbidden special character
    "tenant@org.com",    # @ forbidden
    "a" * 129,           # too long (> 128 chars)
    "tenant/slash",      # slash forbidden
])
def test_invalid_tenant_id_raises(invalid: str) -> None:
    with pytest.raises(TenantResolutionError):
        TenantContext.set_tenant(invalid)


@pytest.mark.parametrize("valid", [
    "tenant-1",
    "tenant_abc",
    "Tenant123",
    "org-saas-prod",
    "a" * 128,           # exactly 128 chars — upper limit
    "T",                 # 1 char — lower limit
    "mon-saas-analytics",
])
def test_valid_tenant_id_accepted(valid: str) -> None:
    TenantContext.set_tenant(valid)
    assert TenantContext.get_tenant() == valid
    _clean()


# ── reset() ──────────────────────────────────────────────────────────────────


def test_reset_restores_previous_value() -> None:
    _clean()
    TenantContext.set_tenant("initial")
    token = TenantContext.set_tenant("updated")
    assert TenantContext.get_tenant() == "updated"
    TenantContext.reset(token)
    assert TenantContext.get_tenant() == "initial"
    _clean()


def test_reset_after_first_set_restores_none() -> None:
    _clean()
    token = TenantContext.set_tenant("first")
    TenantContext.reset(token)
    assert TenantContext.get_tenant_or_none() is None


# ── clear() ──────────────────────────────────────────────────────────────────


def test_clear_removes_tenant() -> None:
    TenantContext.set_tenant("tenant-to-clear")
    TenantContext.clear()
    assert TenantContext.get_tenant_or_none() is None


def test_clear_idempotent() -> None:
    _clean()
    TenantContext.clear()  # double clear must not raise
    TenantContext.clear()
    assert TenantContext.get_tenant_or_none() is None


# ── Thread isolation ──────────────────────────────────────────────────────────


def test_thread_isolation_concurrent_tenants() -> None:
    """Two simultaneous threads must have independent tenant_id values.

    ContextVar guarantees that each thread has its own copy of the context.
    """
    results: dict[str, str] = {}
    errors: list[Exception] = []

    def worker(name: str, tenant_id: str, sleep_ms: int) -> None:
        try:
            TenantContext.set_tenant(tenant_id)
            time.sleep(sleep_ms / 1000)  # artificial overlap
            results[name] = TenantContext.get_tenant()
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=worker, args=("t1", "tenant-A", 80))
    t2 = threading.Thread(target=worker, args=("t2", "tenant-B", 40))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Errors in threads: {errors}"
    assert results["t1"] == "tenant-A", f"t1 read {results['t1']!r}"
    assert results["t2"] == "tenant-B", f"t2 read {results['t2']!r}"


def test_main_thread_unaffected_by_child_thread() -> None:
    """Modifying the tenant in a child thread must not affect the main thread."""
    _clean()
    TenantContext.set_tenant("main-tenant")

    def mutate_in_thread() -> None:
        TenantContext.set_tenant("child-tenant")
        # The child thread reads the value it set
        assert TenantContext.get_tenant() == "child-tenant"

    t = threading.Thread(target=mutate_in_thread)
    t.start()
    t.join()

    # The main thread must still have its own value
    assert TenantContext.get_tenant() == "main-tenant"
    _clean()


# ── Isolation via contextvars.copy_context() ──────────────────────────────────


def test_copy_context_isolates_from_original() -> None:
    """contextvars.copy_context().run() must allow testing in an isolated context."""
    _clean()
    TenantContext.set_tenant("outer-tenant")

    inner_result: dict[str, str | None] = {}

    def inner() -> None:
        TenantContext.set_tenant("inner-tenant")
        inner_result["val"] = TenantContext.get_tenant()

    # Execute in a copy of the context — inner modifications do not propagate
    # to the outer context AND vice versa for new values.
    ctx = contextvars.copy_context()
    ctx.run(inner)

    assert inner_result["val"] == "inner-tenant"
    # The current (outer) context remains unchanged
    assert TenantContext.get_tenant() == "outer-tenant"
    _clean()


def test_many_concurrent_threads_no_leak() -> None:
    """Stress test: 20 simultaneous threads, each with a unique tenant."""
    n = 20
    results: list[str | None] = [None] * n
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        tenant = f"tenant-{idx:03d}"
        try:
            TenantContext.set_tenant(tenant)
            time.sleep(0.01)
            results[idx] = TenantContext.get_tenant()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    for i in range(n):
        assert results[i] == f"tenant-{i:03d}", f"Thread {i}: {results[i]!r}"
