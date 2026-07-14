"""SessionFactory — cookie security validation and response headers.

Flask session cookie security attributes (HttpOnly, Secure, SameSite)
are defined in the application configuration, not on each HTTP response.
This module checks compliance at startup and applies defensive HTTP headers
to SSO Blueprint responses.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SessionFactory:
    """Utility for validating cookie security attributes and HTTP headers.

    Usage in ``superset_config.py`` (optional, recommended in production):

        from superset_auth_kit.security.session import SessionFactory

        def FLASK_APP_MUTATOR(app):
            SessionFactory.validate_app_config(dict(app.config))
    """

    _REQUIRED: dict[str, Any] = {
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
    }

    @classmethod
    def validate_app_config(cls, app_config: dict[str, Any]) -> list[str]:
        """Check the Flask session cookie configuration.

        Logs a warning for each missing or incorrect parameter.
        ``SESSION_COOKIE_SECURE`` is handled separately because it is legitimately
        ``False`` in HTTP development environments.

        Args:
            app_config: Flask configuration dictionary (``dict(app.config)``).

        Returns:
            List of warnings emitted (empty → configuration is compliant).
        """
        warnings: list[str] = []

        for key, expected in cls._REQUIRED.items():
            actual = app_config.get(key)
            if actual != expected:
                msg = (
                    f"[AuthKit] Cookie security: {key}={actual!r} "
                    f"(expected {expected!r}) — security risk in production."
                )
                logger.warning(msg)
                warnings.append(msg)

        if not app_config.get("SESSION_COOKIE_SECURE", False):
            msg = (
                "[AuthKit] SESSION_COOKIE_SECURE=False — "
                "acceptable in HTTP development, mandatory in production HTTPS."
            )
            logger.warning(msg)
            warnings.append(msg)

        if not warnings:
            logger.info("[AuthKit] Session cookie configuration: compliant.")

        return warnings

    @classmethod
    def apply_secure_headers(cls, response: Any) -> Any:
        """Apply defensive HTTP headers to a Flask response.

        Attach via ``@blueprint.after_request``.  Does not touch the session
        cookie (managed by Flask/Flask-Login via global configuration), but
        reinforces the SSO Blueprint redirect responses.

        Headers applied:
        - ``X-Content-Type-Options: nosniff`` — prevents MIME sniffing.
        - ``X-Frame-Options: SAMEORIGIN`` — clickjacking protection.
        - ``Cache-Control: no-store`` — prevents redirect caching.
        - ``Pragma: no-cache`` — HTTP/1.0 backward compatibility.

        Args:
            response: ``flask.Response`` instance.

        Returns:
            The same ``response`` instance, with headers modified in place.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        return response
