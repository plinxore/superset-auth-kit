"""ADR-003 Phase 1: Tenant context lifecycle, concurrent isolation, Fail Closed.

Three test categories:

1. ``TestTenantContextIsolationConcurrent`` (ThreadPoolExecutor)
   Mathematically proves that no inter-thread leakage is possible with ContextVar.
   N parallel workers, each with a unique tenant — deterministic verification.

2. ``TestFailClosedOnMissingContext`` (Flask test client)
   Verifies that global hooks block any SAK request without a valid context
   and that ``current_tenant()`` raises ``TenantContextMissingError`` (Fail Closed).

3. ``TestTeardownGuarantee`` (Flask test client)
   Simulates an exception mid-request and proves that the ContextVar is properly
   cleaned up by ``teardown_request``, even on an unhandled Python exception.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask, abort, g, session

from superset_auth_kit.api.blueprint import _register_global_hooks, create_sso_blueprint
from superset_auth_kit.exceptions import TenantContextMissingError, TenantResolutionError
from superset_auth_kit.tenant.context import TenantContext


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures — minimal Flask app with SAK hooks registered
# ─────────────────────────────────────────────────────────────────────────────


def _make_flask_app(*, authenticated: bool = True, tenant_in_session: str | None = None) -> Flask:
    """Create a minimal Flask app with flask_login + SAK hooks.

    Args:
        authenticated: If True, ``current_user.is_authenticated`` returns True.
        tenant_in_session: Value to place in ``session["_sak_tenant"]`` if not None.

    Returns:
        Flask application configured for tests.
    """
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        # TESTING=True implicitly activates PROPAGATE_EXCEPTIONS (Flask re-raises
        # exceptions instead of returning 500). We disable it so tests can
        # inspect the HTTP response code instead of catching the exception.
        PROPAGATE_EXCEPTIONS=False,
        SECRET_KEY="test-secret-key-not-for-production",
        WTF_CSRF_ENABLED=False,
    )

    # ── Simulate flask_login without Superset ─────────────────────────────────
    try:
        from flask_login import LoginManager, UserMixin, login_user

        class _FakeUser(UserMixin):
            id = "test-user-001"
            username = "test-user-001"

        login_manager = LoginManager()
        login_manager.init_app(app)

        @login_manager.user_loader
        def _load_user(user_id: str) -> _FakeUser | None:
            return _FakeUser() if authenticated else None

        _fake_user = _FakeUser()

        @app.before_request
        def _inject_session_and_user() -> None:
            """Prepare the session and user before each test request."""
            if tenant_in_session is not None:
                session["_sak_tenant"] = tenant_in_session
            if authenticated:
                login_user(_fake_user)

    except ImportError:
        pytest.skip("flask_login not available")

    # ── Register SAK global hooks ─────────────────────────────────────────────
    _register_global_hooks(app)

    # ── Test routes ───────────────────────────────────────────────────────────
    @app.route("/get-tenant")
    def route_get_tenant() -> str:
        """Return the active tenant or raise TenantContextMissingError."""
        return TenantContext.get_tenant()

    @app.route("/raise-sql-error")
    def route_raise_sql_error() -> str:
        """Simulate a SQLAlchemy timeout mid-request."""
        # The context is active here (before the exception)
        assert TenantContext.get_tenant_or_none() is not None
        raise RuntimeError("Simulated SQLAlchemy timeout")

    @app.route("/raise-abort")
    def route_raise_abort() -> str:
        """Simulate a Flask abort() (e.g. 404, 403)."""
        abort(404)

    return app


# ─────────────────────────────────────────────────────────────────────────────
# 1. CONCURRENT ISOLATION TEST
# ─────────────────────────────────────────────────────────────────────────────


class TestTenantContextIsolationConcurrent:
    """Proofs of inter-thread isolation via ContextVar (PEP 567).

    Each thread receives a COPY of the creating thread's context at the moment
    of creation (ContextVar semantics). Modifications in one thread
    NEVER propagate to other threads.
    """

    def test_threadpoolexecutor_10_workers_no_cross_contamination(self) -> None:
        """10 parallel workers, each with a unique UUID tenant.

        Property verified: results[i] == f"tenant-{i:03d}" for all i in [0,9].
        If contamination existed, at least one result would differ from expected.
        """
        n_workers = 10
        results: dict[int, str | None] = {}
        errors: list[str] = []

        def _worker(idx: int) -> None:
            tenant_id = f"tenant-{idx:03d}"
            try:
                token = TenantContext.set_tenant(tenant_id)
                # Sleep inversely proportional to the index to maximize overlaps:
                # thread 9 starts first, thread 0 finishes last.
                time.sleep((n_workers - idx) * 0.005)
                observed = TenantContext.get_tenant()
                results[idx] = observed
                TenantContext.reset(token)
            except Exception as exc:
                errors.append(f"Thread {idx}: {exc!r}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = [executor.submit(_worker, i) for i in range(n_workers)]
            concurrent.futures.wait(futures)

        assert not errors, f"Errors in workers: {errors}"
        assert len(results) == n_workers, f"Missing results: {results}"

        for i in range(n_workers):
            expected = f"tenant-{i:03d}"
            observed = results[i]
            assert observed == expected, (
                f"CONTAMINATION DETECTED: worker {i} expected {expected!r}, "
                f"read {observed!r}. Another thread contaminated the context."
            )

    def test_nested_set_reset_restores_deterministically(self) -> None:
        """Nested set/reset calls restore the exact state at each stack level."""
        TenantContext.clear()

        token_a = TenantContext.set_tenant("tenant-outer")
        assert TenantContext.get_tenant() == "tenant-outer"

        token_b = TenantContext.set_tenant("tenant-inner")
        assert TenantContext.get_tenant() == "tenant-inner"

        TenantContext.reset(token_b)
        assert TenantContext.get_tenant() == "tenant-outer", (
            "reset(token_b) must restore 'tenant-outer', not None"
        )

        TenantContext.reset(token_a)
        assert TenantContext.get_tenant_or_none() is None, (
            "reset(token_a) must restore None (value before the first set)"
        )

    def test_copy_context_run_is_fully_isolated(self) -> None:
        """contextvars.copy_context().run() creates an isolated copy of the context.

        Modifications inside the copy do not propagate back to the current context.
        This pattern is used by Celery, asyncio.Task, and isolation tests.
        """
        TenantContext.clear()
        token = TenantContext.set_tenant("host-tenant")

        inner_saw: list[str | None] = []
        host_after_inner: list[str | None] = []

        def _inner_context() -> None:
            # Inside the copy: the initial value is inherited ("host-tenant")
            inner_saw.append(TenantContext.get_tenant_or_none())
            # Modification inside the copy — must be invisible in the host context
            TenantContext.set_tenant("copy-tenant")
            inner_saw.append(TenantContext.get_tenant())

        ctx_copy = contextvars.copy_context()
        ctx_copy.run(_inner_context)

        # The host context must be unchanged after the copy executes
        host_after_inner.append(TenantContext.get_tenant_or_none())

        assert inner_saw[0] == "host-tenant", (
            "The copy must inherit the host context's value at the time of copying"
        )
        assert inner_saw[1] == "copy-tenant", (
            "Inside the copy, set_tenant must modify the local value"
        )
        assert host_after_inner[0] == "host-tenant", (
            "The host context MUST NOT be affected by modifications inside the copy"
        )

        TenantContext.reset(token)

    def test_thread_writing_to_its_own_context_does_not_affect_main(self) -> None:
        """A child thread calling set_tenant does not affect the main thread."""
        TenantContext.clear()
        main_token = TenantContext.set_tenant("main-thread-tenant")

        child_result: list[str] = []
        child_contaminated_main: list[str | None] = []

        def _child() -> None:
            # The child thread starts with its own context (copy of the parent)
            # but any modification is local to this thread.
            child_token = TenantContext.set_tenant("child-thread-tenant")
            time.sleep(0.02)
            child_result.append(TenantContext.get_tenant())
            TenantContext.reset(child_token)

        t = threading.Thread(target=_child)
        t.start()
        # The main thread continues to read its own value while the child runs
        time.sleep(0.01)
        child_contaminated_main.append(TenantContext.get_tenant_or_none())
        t.join()

        assert child_result == ["child-thread-tenant"]
        assert child_contaminated_main == ["main-thread-tenant"], (
            f"The child thread contaminated the main thread: {child_contaminated_main}"
        )

        TenantContext.reset(main_token)
        assert TenantContext.get_tenant_or_none() is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. FAIL CLOSED TESTS
# ─────────────────────────────────────────────────────────────────────────────


class TestFailClosedOnMissingContext:
    """Verifies the Fail Closed policy (ADR-306) on critical paths."""

    def test_get_tenant_raises_tenant_context_missing_error(self) -> None:
        """get_tenant() without prior set_tenant() → TenantContextMissingError."""
        TenantContext.clear()
        with pytest.raises(TenantContextMissingError) as exc_info:
            TenantContext.get_tenant()
        assert "tenant_id" in str(exc_info.value).lower() or "context" in str(exc_info.value).lower()

    def test_tenant_context_missing_is_subclass_of_resolution_error(self) -> None:
        """TenantContextMissingError is catchable via except TenantResolutionError."""
        TenantContext.clear()
        with pytest.raises(TenantResolutionError):
            TenantContext.get_tenant()

    def test_invalid_tenant_id_raises_tenant_resolution_error_not_missing(self) -> None:
        """set_tenant() with invalid value → TenantResolutionError (not TenantContextMissingError)."""
        with pytest.raises(TenantResolutionError) as exc_info:
            TenantContext.set_tenant("invalid tenant!")
        # The value is invalid (format), not absent (missing context)
        assert not isinstance(exc_info.value, TenantContextMissingError), (
            "TenantResolutionError for invalid format MUST NOT be TenantContextMissingError"
        )

    def test_flask_before_request_aborts_403_when_invalid_tenant_in_session(self) -> None:
        """Invalid tenant (regex fail) in session → 403 Forbidden (Fail Closed)."""
        app = _make_flask_app(authenticated=True, tenant_in_session="invalid tenant!")
        with app.test_client() as client:
            response = client.get("/get-tenant")
        assert response.status_code == 403, (
            f"An invalid tenant in session must return 403, got {response.status_code}"
        )

    def test_flask_authenticated_user_with_valid_tenant_gets_200(self) -> None:
        """Authenticated request with valid tenant → context hydrated → 200."""
        app = _make_flask_app(authenticated=True, tenant_in_session="valid-tenant-001")
        with app.test_client() as client:
            response = client.get("/get-tenant")
        assert response.status_code == 200
        assert response.data == b"valid-tenant-001"

    def test_flask_unauthenticated_user_skips_tenant_hydration(self) -> None:
        """Unauthenticated request → before_request skip → context not hydrated.

        The /get-tenant route raises TenantContextMissingError → 500 (no filter).
        This is the expected Fail Closed behavior: routes requiring the tenant
        context are not accessible without SSO authentication.
        """
        app = _make_flask_app(authenticated=False, tenant_in_session="tenant-should-be-skipped")
        with app.test_client() as client:
            response = client.get("/get-tenant")
        # Without auth, context is not hydrated → get_tenant() raises → 500
        assert response.status_code in (500, 403), (
            f"Expected 500 or 403 (Fail Closed), got {response.status_code}"
        )

    def test_flask_sak_user_without_tenant_key_is_not_blocked(self) -> None:
        """Authenticated SAK user without _sak_tenant key → skip (non-SAK path).

        This case corresponds to a Superset admin: ``session["_sak_tenant"]`` is absent.
        The hook does NOT block (no 403) — it simply skips hydration.
        """
        # No tenant_in_session → before_request sees current_user.is_authenticated=True
        # but no _sak_tenant → skip.
        # The /get-tenant route will then raise TenantContextMissingError → 500.
        # This is correct: tenant-aware routes are not accessible without an SAK tenant.
        app = _make_flask_app(authenticated=True, tenant_in_session=None)
        with app.test_client() as client:
            response = client.get("/get-tenant")
        # No 403 (hook did not block), but get_tenant() raises because context is absent
        assert response.status_code == 500, (
            "Without _sak_tenant, the hook skips hydration, get_tenant() raises → 500"
        )

    @pytest.mark.parametrize("invalid_tenant", [
        # NOTE: "admin" is NOT in this list — "admin" is a valid format
        # according to ^[a-zA-Z0-9_-]{1,128}$. The anti-admin protection applies to
        # ROLE NAMES (RoleMapper / ADR-002), not tenant_id values.
        "tenant with space",       # space forbidden
        "t" * 129,                 # too long
        "tenant@domain.com",       # @ forbidden
        "'; DROP TABLE users; --", # SQL injection attempt
        "../../../etc/passwd",     # path traversal
        "",                        # empty
    ])
    def test_sql_injection_via_tenant_id_is_blocked_at_set_tenant(
        self, invalid_tenant: str
    ) -> None:
        """Any potentially dangerous tenant_id value is rejected by the regex.

        Validation is at write time (set_tenant) — never at read time.
        If the value is not in the ContextVar, it cannot reach the SQL.
        """
        with pytest.raises(TenantResolutionError):
            TenantContext.set_tenant(invalid_tenant)
        # Verify that nothing was written to the ContextVar
        assert TenantContext.get_tenant_or_none() != invalid_tenant, (
            "An invalid value MUST NEVER be written to the ContextVar"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. TEARDOWN GUARANTEE TESTS (teardown_request)
# ─────────────────────────────────────────────────────────────────────────────


class TestTeardownGuarantee:
    """Verifies that teardown_request cleans up the ContextVar even on exception."""

    def test_contextvar_is_none_after_successful_request(self) -> None:
        """After a successful request, the ContextVar must be None (cleaned up)."""
        app = _make_flask_app(authenticated=True, tenant_in_session="tenant-success")

        with app.test_client() as client:
            response = client.get("/get-tenant")
            assert response.status_code == 200
            assert response.data == b"tenant-success"

        # AFTER the request, the ContextVar must be None in this thread (test thread).
        # The Flask test client is synchronous — the request has finished and teardown ran.
        assert TenantContext.get_tenant_or_none() is None, (
            "After a successful request, the ContextVar must be None (teardown executed)"
        )

    def test_contextvar_is_none_after_python_exception_in_view(self) -> None:
        """After an uncaught Python exception in the view → teardown guarantees cleanup."""
        app = _make_flask_app(authenticated=True, tenant_in_session="tenant-raises")

        # Register an error handler to avoid Flask returning a confusing 500
        @app.errorhandler(RuntimeError)
        def _handle_runtime(e: RuntimeError) -> tuple[str, int]:
            return "simulated error", 500

        with app.test_client() as client:
            response = client.get("/raise-sql-error")
            # The view raises RuntimeError → error handler → 500
            assert response.status_code == 500

        # Even after the exception, teardown_request ran correctly
        assert TenantContext.get_tenant_or_none() is None, (
            "After a RuntimeError in the view, teardown_request MUST clean up the ContextVar"
        )

    def test_contextvar_is_none_after_abort_in_view(self) -> None:
        """After a Flask abort() in the view → teardown guarantees cleanup."""
        app = _make_flask_app(authenticated=True, tenant_in_session="tenant-abort")

        with app.test_client() as client:
            response = client.get("/raise-abort")
            assert response.status_code == 404

        assert TenantContext.get_tenant_or_none() is None, (
            "After an abort(404) in the view, teardown_request MUST clean up the ContextVar"
        )

    def test_contextvar_is_none_after_before_request_abort(self) -> None:
        """When before_request does abort(403) (invalid tenant), teardown still cleans up."""
        app = _make_flask_app(authenticated=True, tenant_in_session="invalid tenant!")

        with app.test_client() as client:
            response = client.get("/get-tenant")
            assert response.status_code == 403

        # before_request aborted before set_tenant → no token in g
        # → teardown calls clear() as safety net → None
        assert TenantContext.get_tenant_or_none() is None, (
            "After abort(403) in before_request, teardown MUST clean up via clear()"
        )

    def test_multiple_sequential_requests_never_leak_between_them(self) -> None:
        """Multiple successive requests on the same client do not share context."""
        app = _make_flask_app(authenticated=True, tenant_in_session="tenant-sequential")

        with app.test_client() as client:
            for i in range(5):
                resp = client.get("/get-tenant")
                assert resp.status_code == 200
                assert resp.data == b"tenant-sequential"
                # Between requests (synchronous), the context is clean
                assert TenantContext.get_tenant_or_none() is None, (
                    f"Request {i}: context not cleaned between sequential requests"
                )

    def test_token_reset_is_deterministic_and_not_clear(self) -> None:
        """reset(token) restores exactly the previous state, even if it was a value."""
        # Stack two values to verify that reset restores the intermediate value,
        # not just None.
        TenantContext.clear()
        outer_token = TenantContext.set_tenant("outer-tenant")
        # Simulate a before_request that overwrites an already-present value
        inner_token = TenantContext.set_tenant("inner-tenant")
        assert TenantContext.get_tenant() == "inner-tenant"

        # teardown of inner request → reset(inner_token)
        TenantContext.reset(inner_token)
        assert TenantContext.get_tenant() == "outer-tenant", (
            "reset(inner_token) must restore 'outer-tenant', not None"
        )

        # teardown of outer request → reset(outer_token)
        TenantContext.reset(outer_token)
        assert TenantContext.get_tenant_or_none() is None

    def test_concurrent_requests_teardown_isolated(self) -> None:
        """Under concurrency, teardown in one thread does not clean another thread's context.

        Property: each thread has its own ContextVar — reset in one thread
        does not modify the ContextVar value in another thread.
        """
        barrier = threading.Barrier(2)
        results_after_teardown: dict[str, str | None] = {}

        def _worker(name: str, tenant: str, teardown_first: bool) -> None:
            token = TenantContext.set_tenant(tenant)
            barrier.wait()  # Both threads have set their value

            if teardown_first:
                # This thread resets WHILE the other is still active
                TenantContext.reset(token)
                results_after_teardown[name] = TenantContext.get_tenant_or_none()
            else:
                # This thread waits for the other to reset
                time.sleep(0.02)
                # Its value must not have been affected by the other's reset
                results_after_teardown[name] = TenantContext.get_tenant_or_none()
                TenantContext.reset(token)

        t1 = threading.Thread(target=_worker, args=("t1", "tenant-T1", True))
        t2 = threading.Thread(target=_worker, args=("t2", "tenant-T2", False))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results_after_teardown["t1"] is None, (
            "After reset(token), t1 must be None"
        )
        assert results_after_teardown["t2"] == "tenant-T2", (
            f"t1's reset MUST NOT affect t2: {results_after_teardown['t2']!r}"
        )
