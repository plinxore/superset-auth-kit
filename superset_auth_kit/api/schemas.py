"""Marshmallow schemas for AuthKit API request validation.

The only critical security rule in this module:
``validate_redirect_path`` must reject any absolute or protocol-relative URL
to eliminate open redirect attacks (CWE-601).
"""

from __future__ import annotations

from typing import Any

from marshmallow import Schema, ValidationError, fields, validates_schema


def validate_redirect_path(path: str) -> None:
    """Raise ``ValidationError`` if *path* is not a safe relative path.

    Rejection criteria (defense in depth):
    - Does not start with ``/`` → absolute URL or implicit path.
    - Starts with ``//`` → protocol-relative URL (exploitable as external redirect).
    - Contains ``://`` → explicit scheme (``http://``, ``https://``, ``javascript://``…).

    Args:
        path: Value of ``redirect_to`` to validate.

    Raises:
        ValidationError: If *path* is an absolute or protocol-relative URL.
    """
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        raise ValidationError(
            "Must be a relative path starting with '/' "
            "(e.g. /superset/dashboard/1/). "
            "Absolute URLs and external redirects are not allowed."
        )


class SsoRequestSchema(Schema):
    """Validation schema for the ``POST /api/v1/auth/sso`` payload.

    Fields:
        token: Raw token (JWT or opaque) issued by the IdP.  Required.
        redirect_to: Post-authentication redirect path.  Optional.
            Must start with ``/`` and must not be an absolute URL.
            Default: ``/superset/welcome/``.
    """

    token = fields.Str(
        required=True,
        metadata={"description": "JWT or opaque token issued by the IdP."},
    )
    redirect_to = fields.Str(
        load_default="/superset/welcome/",
        metadata={"description": "Redirect path after authentication."},
    )

    @validates_schema
    def check_redirect(self, data: dict[str, Any], **kwargs: Any) -> None:
        """Validate ``redirect_to`` after deserialization (defense in depth).

        This validation is redundant with the view's validation, but the double
        check ensures that no invalid path can traverse the schema.
        """
        validate_redirect_path(data.get("redirect_to", "/superset/welcome/"))
