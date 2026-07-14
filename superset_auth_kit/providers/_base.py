"""Abstraction contract for identity sources (Provider Pattern, PEP 544).

This module defines:
- :class:`Identity`: frozen dataclass representing a normalized identity,
  independent of the source provider (JWT, OIDC, SAML, API key, …).
- :class:`IdentityProvider`: structural Protocol (PEP 544) that every
  provider implementation must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class Identity:
    """Normalized representation of an authenticated identity.

    The dataclass is ``frozen=True`` to guarantee immutability after
    construction.  Fields used in the fingerprint computation
    (email, first name, last name, roles, tenant) are included in ``__eq__``
    and ``__hash__``; ``metadata`` is explicitly excluded to avoid breaking
    the hash on arbitrary values.

    Attributes:
        sub: Stable unique identifier for the user (OIDC ``sub``).
            Used as ``username`` in the FAB ``ab_user`` table.
            Must never change for the same physical user.
        email: E-mail address.
        first_name: Given name.
        last_name: Family name.
        roles: Role names as declared by the identity provider.
            Stored as a ``tuple`` (hashable) rather than a ``list``.
        tenant_id: Multi-tenant discriminant.  Validated by
            :class:`~superset_auth_kit.tenant.context.TenantContext`
            before any storage in the execution context.
        issued_at: Token issuance timestamp (``iat``).
        expires_at: Token expiration timestamp (``exp``).
        metadata: Additional claims passed to the Jinja SQL template engine
            for Row Level Security.  Excluded from ``__hash__`` and ``__eq__``.
    """

    sub: str
    email: str
    first_name: str
    last_name: str
    roles: tuple[str, ...]
    tenant_id: str
    issued_at: datetime
    expires_at: datetime
    metadata: dict[str, Any] = field(
        default_factory=dict,
        hash=False,
        compare=False,
    )

    def as_userinfo_dict(self) -> dict[str, Any]:
        """Return a dict compatible with the FAB ``auth_user_oauth(userinfo)`` signature.

        Used by :class:`~superset_auth_kit.security.manager.AuthKitSecurityManager`
        to delegate to the standard FAB authentication cycle.
        """
        return {
            "username": self.sub,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
        }


@runtime_checkable
class IdentityProvider(Protocol):
    """Structural protocol for all identity sources (PEP 544).

    Implementations do **not** need to inherit from this class.
    Static duck-typing (mypy, pyright) validates conformance at compile time;
    ``isinstance(obj, IdentityProvider)`` checks only for the presence of the
    ``authenticate`` method at runtime thanks to ``@runtime_checkable``.

    Planned providers:
    - ``JwtProvider`` (HS256 / RS256) — v1.0
    - ``OidcProvider`` (RFC 7662 introspection) — v1.1
    - ``KeycloakProvider`` (JWKS auto-refresh) — v1.1
    - ``ApiKeyProvider`` (SHA-256 hash lookup) — v1.1
    """

    def authenticate(self, raw_token: str) -> Identity:
        """Validate *raw_token* and return a normalized :class:`Identity`.

        Args:
            raw_token: Raw token as received from the client (JWT, opaque token, …).

        Returns:
            An immutable :class:`Identity` representing the authenticated user.

        Raises:
            TokenExpiredError: The token has exceeded its ``exp``.
            TokenInvalidError: Invalid signature, malformation, or missing claim.
        """
        ...
