"""Thread-safe and coroutine-safe tenant context based on ``contextvars.ContextVar``.

Uses :class:`contextvars.ContextVar` (PEP 567) rather than ``threading.local``
or mutating ``flask.g`` for three reasons:

1. **Isolation**: each Gunicorn thread (gthread worker) and each asyncio coroutine
   receives a distinct execution context — no leakage between concurrent requests
   handled by the same thread.
2. **Determinism**: the current value is always the last one set in the current
   call tree, not a shared global variable.
3. **Testability**: ``contextvars.copy_context().run(fn)`` allows isolating
   contexts in unit tests without mocking ``flask.g``.

RLS Jinja integration — in ``superset_config.py``:

    from superset_auth_kit.tenant.context import TenantContext

    JINJA_CONTEXT_ADDONS = {
        "current_tenant": TenantContext.get_tenant,
    }

Then in a SQL template:

    WHERE tenant_id = '{{ current_tenant() }}'

The value returned by :meth:`TenantContext.get_tenant` is sanitized on write
(pattern ``^[a-zA-Z0-9_-]{1,128}$``), making SQL injection structurally impossible.
"""

from __future__ import annotations

import re
from contextvars import ContextVar, Token
from typing import Optional

from superset_auth_kit.exceptions import TenantContextMissingError, TenantResolutionError

# Only alphanumeric characters, hyphens, and underscores are accepted.
# This regex is the first line of defense against SQL/Jinja injection.
_TENANT_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")

# Context variable initialized to None.
# The name "authkit_tenant_id" appears in contextvars debug traces.
_tenant_ctx: ContextVar[Optional[str]] = ContextVar(
    "authkit_tenant_id", default=None
)


class TenantContext:
    """Static API for reading and writing the tenant in the current execution context.

    All methods are static: no instance state, no injection required.
    The underlying ContextVar is module-level to guarantee that only one
    variable exists per process.

    Recommended lifecycle in the SSO view:

        token = TenantContext.set_tenant(identity.tenant_id)
        try:
            # ... request processing ...
        finally:
            TenantContext.reset(token)  # restores the previous value
    """

    @staticmethod
    def set_tenant(tenant_id: str) -> Token:
        """Validate and store *tenant_id* in the current execution context.

        Args:
            tenant_id: Tenant identifier extracted from a **previously validated** token.
                Must match the pattern ``^[a-zA-Z0-9_-]{1,128}$``.

        Returns:
            A :class:`~contextvars.Token` allowing the previous value to be restored
            via :meth:`reset`.

        Raises:
            TenantResolutionError: If *tenant_id* is empty or does not match
                the sanitization pattern.
        """
        if not tenant_id or not _TENANT_PATTERN.fullmatch(tenant_id):
            raise TenantResolutionError(
                f"tenant_id {tenant_id!r} is invalid.  "
                f"Only alphanumeric characters, hyphens, and underscores "
                f"are accepted (1 to 128 characters)."
            )
        return _tenant_ctx.set(tenant_id)

    @staticmethod
    def get_tenant() -> str:
        """Return the tenant for the current request.

        Designed to be referenced in ``JINJA_CONTEXT_ADDONS`` and called
        from RLS SQL templates.

        Returns:
            The tenant identifier validated and stored by :meth:`set_tenant`.

        Raises:
            TenantResolutionError: No tenant is defined in the current context
                (called outside an SSO-authenticated request).
        """
        value: Optional[str] = _tenant_ctx.get()
        if value is None:
            raise TenantContextMissingError(
                "No tenant_id is defined for the current execution context. "
                "Verify that the before_request hook has hydrated the context "
                "(session '_sak_tenant' present and user authenticated via SSO)."
            )
        return value

    @staticmethod
    def get_tenant_or_none() -> Optional[str]:
        """Return the tenant or ``None`` without raising an exception.

        Useful in handlers where the tenant is optional
        (e.g. application health checks, unauthenticated endpoints).
        """
        return _tenant_ctx.get()

    @staticmethod
    def reset(token: Token) -> None:
        """Restore the context value to the state before :meth:`set_tenant` was called.

        Must be called in a ``finally`` block to prevent any context leakage
        between requests handled by the same thread.

        Args:
            token: The :class:`~contextvars.Token` returned by :meth:`set_tenant`.
        """
        _tenant_ctx.reset(token)

    @staticmethod
    def clear() -> None:
        """Unconditionally reset the tenant to ``None``.

        Prefer :meth:`reset` when a restoration token is available.
        Use this method only in teardown hooks where the token is no longer accessible.
        """
        _tenant_ctx.set(None)
