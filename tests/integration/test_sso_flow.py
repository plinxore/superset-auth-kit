"""E2E integration tests — SSO flow against an ephemeral Docker Superset instance.

These tests require Docker and are excluded from fast runs by default.
Launch with:
    pytest -v -m integration tests/integration/

The Superset container is provided by the ``superset_container`` fixture
defined in ``tests/integration/conftest.py``.
"""

from __future__ import annotations

import time
import uuid

import jwt as pyjwt
import pytest

try:
    import requests as _req_module
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

pytestmark = pytest.mark.integration

# ── Constants shared with superset_config_test.py ────────────────────────────

_JWT_SECRET = "test-jwt-secret-integration"
_ALGORITHMS = ["HS256"]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_token(
    *,
    sub: str = "integration-user",
    tenant_id: str = "tenant-integration",
    exp_delta: int = 300,
    include_jti: bool = False,
) -> str:
    now = int(time.time())
    claims: dict = {
        "sub": sub,
        "email": f"{sub}@example.com",
        "given_name": "Integration",
        "family_name": "Test",
        "roles": ["viewer"],
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + exp_delta,
    }
    if include_jti:
        claims["jti"] = str(uuid.uuid4())
    return pyjwt.encode(claims, _JWT_SECRET, algorithm="HS256")


def _sso_post(base_url: str, token: str, redirect_to: str = "/superset/welcome/") -> "_req_module.Response":
    import requests

    return requests.post(
        f"{base_url}/api/v1/auth/sso",
        json={"token": token, "redirect_to": redirect_to},
        allow_redirects=False,
        timeout=15,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_sso_flow_nominal(superset_container: str) -> None:
    """Nominal flow: POST valid JWT → 302 + Flask session cookie present."""
    base_url = superset_container
    token = _make_token()

    resp = _sso_post(base_url, token)

    assert resp.status_code == 302, (
        f"Expected 302, got {resp.status_code}. Body: {resp.text[:500]}"
    )
    assert "/superset/welcome/" in resp.headers.get("Location", ""), (
        f"Unexpected Location header: {resp.headers.get('Location')}"
    )
    # Flask session cookie must be present in the response
    assert "session" in resp.cookies, (
        f"Cookie 'session' absent. Cookies received: {dict(resp.cookies)}"
    )


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_sso_flow_redirect_to_custom_path(superset_container: str) -> None:
    """The redirect_to is honored for any valid relative path."""
    base_url = superset_container
    token = _make_token(sub="redirect-user")

    resp = _sso_post(base_url, token, redirect_to="/superset/dashboard/list/")

    assert resp.status_code == 302
    assert "/superset/dashboard/list/" in resp.headers.get("Location", "")


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_sso_flow_expired_token_returns_400(superset_container: str) -> None:
    """Expired token → 400 (no session created)."""
    base_url = superset_container
    token = _make_token(exp_delta=-60)  # expired 60s ago

    resp = _sso_post(base_url, token)

    assert resp.status_code == 400
    assert "session" not in resp.cookies


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_sso_flow_invalid_signature_returns_401(superset_container: str) -> None:
    """Token signed with wrong secret → 401."""
    base_url = superset_container
    token = pyjwt.encode(
        {"sub": "hack", "email": "h@h.com", "given_name": "H", "family_name": "H",
         "roles": ["viewer"], "tenant_id": "t1",
         "iat": int(time.time()), "exp": int(time.time()) + 300},
        "wrong-secret",
        algorithm="HS256",
    )

    resp = _sso_post(base_url, token)

    assert resp.status_code == 401


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_replay_attack_protection(superset_container: str) -> None:
    """Anti-replay jti: first presentation → 302, second → 403."""
    base_url = superset_container
    # Token with unique jti
    token = _make_token(sub=f"replay-user-{uuid.uuid4().hex[:8]}", include_jti=True)

    # First presentation — must succeed
    resp1 = _sso_post(base_url, token)
    assert resp1.status_code == 302, (
        f"1st presentation expected 302, got {resp1.status_code}. Body: {resp1.text[:300]}"
    )

    # Second presentation of the SAME token — must be blocked
    resp2 = _sso_post(base_url, token)
    assert resp2.status_code == 403, (
        f"2nd presentation expected 403 (anti-replay), got {resp2.status_code}. Body: {resp2.text[:300]}"
    )


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_invalid_redirect_to_returns_400(superset_container: str) -> None:
    """Absolute URL in redirect_to → 400 (anti open-redirect, Marshmallow schema side)."""
    import requests

    base_url = superset_container
    token = _make_token()

    resp = requests.post(
        f"{base_url}/api/v1/auth/sso",
        json={"token": token, "redirect_to": "https://evil.com/steal"},
        allow_redirects=False,
        timeout=15,
    )

    assert resp.status_code == 400


@pytest.mark.skipif(not _REQUESTS_AVAILABLE, reason="requests not installed")
def test_tenant_injection_jinja(superset_container: str) -> None:
    """Verify that an SSO user can access Superset after authentication.

    A full test of Jinja rendering (``current_tenant()``) requires creating a
    dataset and chart with RLS template enabled, which is out of scope for this
    smoke test.  We verify here that:
    1. The SSO session is valid (200 on a protected page).
    2. The session cookie is accepted by Superset.
    """
    import requests

    base_url = superset_container
    token = _make_token(sub=f"jinja-user-{uuid.uuid4().hex[:8]}", tenant_id="tenant-jinja-test")

    session = requests.Session()
    sso_resp = session.post(
        f"{base_url}/api/v1/auth/sso",
        json={"token": token, "redirect_to": "/superset/welcome/"},
        allow_redirects=False,
        timeout=15,
    )
    assert sso_resp.status_code == 302, f"SSO failed: {sso_resp.status_code}"

    # Follow the redirect with the session cookie
    welcome_resp = session.get(f"{base_url}/superset/welcome/", timeout=15)
    # 200 = page loaded / 302 to login = invalid session
    assert welcome_resp.status_code == 200, (
        f"Invalid session after SSO: code={welcome_resp.status_code}. "
        f"Check CUSTOM_SECURITY_MANAGER in superset_config_test.py."
    )
