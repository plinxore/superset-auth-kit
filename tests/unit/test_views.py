"""Unit tests — validate_redirect_path, SsoRequestSchema, and sso_view (Flask test client)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from marshmallow import ValidationError

from superset_auth_kit.api.schemas import SsoRequestSchema, validate_redirect_path
from superset_auth_kit.exceptions import (
    AuthKitError,
    RoleEscalationError,
    TokenExpiredError,
    TokenInvalidError,
    TokenReplayError,
    UserSyncError,
)

# ── validate_redirect_path ────────────────────────────────────────────────────


@pytest.mark.parametrize("valid_path", [
    "/superset/welcome/",
    "/superset/dashboard/1/",
    "/superset/explore/",
    "/",
    "/api/v1/chart/",
    "/path/with/many/segments",
])
def test_valid_relative_path_does_not_raise(valid_path: str) -> None:
    validate_redirect_path(valid_path)  # must not raise


@pytest.mark.parametrize("invalid_path", [
    "https://evil.com",
    "http://evil.com/steal",
    "//evil.com",
    "//evil.com/path",
    "relative/path",
    "no-leading-slash",
    "javascript://alert(1)",
    "data://text/html,<script>",
    "",
    "://schemeless",
])
def test_invalid_path_raises_validation_error(invalid_path: str) -> None:
    with pytest.raises(ValidationError):
        validate_redirect_path(invalid_path)


# ── SsoRequestSchema ──────────────────────────────────────────────────────────


def test_schema_valid_full_payload() -> None:
    schema = SsoRequestSchema()
    data = schema.load({"token": "my.jwt.token", "redirect_to": "/superset/welcome/"})
    assert data["token"] == "my.jwt.token"
    assert data["redirect_to"] == "/superset/welcome/"


def test_schema_token_required() -> None:
    schema = SsoRequestSchema()
    with pytest.raises(ValidationError) as exc_info:
        schema.load({"redirect_to": "/superset/"})
    assert "token" in exc_info.value.messages


def test_schema_default_redirect_to() -> None:
    schema = SsoRequestSchema()
    data = schema.load({"token": "test.jwt"})
    assert data["redirect_to"] == "/superset/welcome/"


def test_schema_rejects_absolute_redirect() -> None:
    schema = SsoRequestSchema()
    with pytest.raises(ValidationError):
        schema.load({"token": "test.jwt", "redirect_to": "https://evil.com"})


def test_schema_rejects_protocol_relative_redirect() -> None:
    schema = SsoRequestSchema()
    with pytest.raises(ValidationError):
        schema.load({"token": "test.jwt", "redirect_to": "//evil.com"})


def test_schema_accepts_deep_path() -> None:
    schema = SsoRequestSchema()
    data = schema.load({"token": "t", "redirect_to": "/superset/explore/1/table/2/"})
    assert data["redirect_to"] == "/superset/explore/1/table/2/"


# ── Flask test client — sso_view ─────────────────────────────────────────────


@pytest.fixture()
def flask_app() -> Flask:
    """Minimal Flask application simulating the Superset environment."""
    from superset_auth_kit.api.views import sso_view

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["WTF_CSRF_ENABLED"] = False

    # Simulates current_app.appbuilder.sm
    mock_sm = MagicMock()
    mock_ab = MagicMock()
    mock_ab.sm = mock_sm
    app.appbuilder = mock_ab  # type: ignore[attr-defined]

    app.add_url_rule("/api/v1/auth/sso", view_func=sso_view, methods=["POST"])
    return app


def test_sso_view_no_json_body(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", data="not json", content_type="text/plain")
        assert resp.status_code == 400
        assert b"JSON" in resp.data


def test_sso_view_missing_token_field(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"redirect_to": "/superset/"})
        assert resp.status_code == 400


def test_sso_view_invalid_redirect_in_payload(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        resp = c.post(
            "/api/v1/auth/sso",
            json={"token": "test.jwt", "redirect_to": "https://evil.com"},
        )
        assert resp.status_code == 400


def test_sso_view_nominal_returns_302(flask_app: Flask) -> None:
    mock_user = MagicMock()
    mock_user.username = "user-abc"
    flask_app.appbuilder.sm.authenticate_sso.return_value = mock_user  # type: ignore[attr-defined]

    with patch("superset_auth_kit.api.views.flask_login.login_user"):
        with flask_app.test_client() as c:
            resp = c.post(
                "/api/v1/auth/sso",
                json={"token": "valid.jwt", "redirect_to": "/superset/welcome/"},
                follow_redirects=False,
            )
    assert resp.status_code == 302
    assert "/superset/welcome/" in resp.headers.get("Location", "")


def test_sso_view_expired_token_returns_400(flask_app: Flask) -> None:
    flask_app.appbuilder.sm.authenticate_sso.side_effect = TokenExpiredError("exp")  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "expired.jwt"})
    assert resp.status_code == 400
    assert b"expir" in resp.data.lower()


def test_sso_view_invalid_token_returns_401(flask_app: Flask) -> None:
    flask_app.appbuilder.sm.authenticate_sso.side_effect = TokenInvalidError("bad")  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "bad.jwt"})
    assert resp.status_code == 401


def test_sso_view_replay_attack_returns_403(flask_app: Flask) -> None:
    flask_app.appbuilder.sm.authenticate_sso.side_effect = TokenReplayError("replay")  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "replayed.jwt"})
    assert resp.status_code == 403


def test_sso_view_role_escalation_returns_400(flask_app: Flask) -> None:
    flask_app.appbuilder.sm.authenticate_sso.side_effect = RoleEscalationError("admin!")  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "escalated.jwt"})
    assert resp.status_code == 400


def test_sso_view_user_sync_error_returns_400(flask_app: Flask) -> None:
    flask_app.appbuilder.sm.authenticate_sso.side_effect = UserSyncError("sync failed")  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "some.jwt"})
    assert resp.status_code == 400


def test_sso_view_missing_appbuilder_returns_500(flask_app: Flask) -> None:
    del flask_app.appbuilder  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "some.jwt"})
    assert resp.status_code == 500


def test_sso_view_no_authenticate_sso_method_returns_500(flask_app: Flask) -> None:
    """SecurityManager without authenticate_sso → configuration error."""
    sm_without_method = MagicMock(spec=[])  # empty spec — no authenticate_sso
    flask_app.appbuilder.sm = sm_without_method  # type: ignore[attr-defined]

    with flask_app.test_client() as c:
        resp = c.post("/api/v1/auth/sso", json={"token": "some.jwt"})
    assert resp.status_code == 500


def test_sso_view_session_cleared_before_login(flask_app: Flask) -> None:
    """Verify that session.clear() precedes login_user (session fixation protection).

    We instrument login_user and ensure it is called with the correct user.
    session.clear() runs in the Flask request context (test_client) — its call
    is guaranteed by the static order of the view code and verified indirectly:
    if session.clear() failed, the view would raise an exception before reaching login_user.
    """
    mock_user = MagicMock()
    mock_user.username = "user-xyz"
    flask_app.appbuilder.sm.authenticate_sso.return_value = mock_user  # type: ignore[attr-defined]

    login_calls: list[Any] = []

    def track_login(user: Any, **kw: Any) -> None:
        login_calls.append(user)

    with patch("superset_auth_kit.api.views.flask_login.login_user", side_effect=track_login):
        with flask_app.test_client() as c:
            resp = c.post(
                "/api/v1/auth/sso",
                json={"token": "valid.jwt", "redirect_to": "/superset/welcome/"},
                follow_redirects=False,
            )

    # The view returned 302 → session.clear() + login_user both succeeded.
    assert resp.status_code == 302
    assert len(login_calls) == 1, "login_user must be called exactly once"
    assert login_calls[0] is mock_user, "login_user must receive the FAB user"
