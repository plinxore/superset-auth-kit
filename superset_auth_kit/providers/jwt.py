"""JWT-based identity provider (HS256 / RS256 / ES256).

Strict PyJWT 2.x rule: the ``algorithms`` parameter is **mandatory** in every
call to ``jwt.decode()`` to prevent algorithm confusion attacks
(CVE-2022-29217 and derivatives).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import jwt as pyjwt
from jwt import ExpiredSignatureError, InvalidTokenError

from superset_auth_kit.exceptions import TokenExpiredError, TokenInvalidError, TokenReplayError
from superset_auth_kit.providers._base import Identity

if TYPE_CHECKING:
    from superset_auth_kit.replay.blocklist import JtiStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClaimMapping:
    """Mapping between JWT claim names and :class:`~superset_auth_kit.providers._base.Identity` fields.

    Overriding the fields allows adapting the provider to any claim schema
    without changing the validation logic.

    Common examples:
    - Auth0: ``first_name="given_name"``, ``last_name="family_name"``
    - Keycloak: ``roles="realm_access.roles"`` (nested path — handled by :class:`JwtProvider`)
    - Custom IdP: ``tenant_id="org_id"``
    """

    sub: str = "sub"
    email: str = "email"
    first_name: str = "given_name"
    last_name: str = "family_name"
    roles: str = "roles"
    tenant_id: str = "tenant_id"


@dataclass
class JwtProvider:
    """Validate a JWT and return a normalized :class:`~superset_auth_kit.providers._base.Identity`.

    Supports symmetric keys (HS256) and asymmetric keys (RS256, ES256).
    The ``algorithms`` parameter is **always** passed explicitly to
    ``jwt.decode()`` — mandatory behavior since PyJWT 2.x.

    Args:
        secret_or_key: Shared secret (HS*) or PEM public key (RS*/ES*).
        algorithms: Exact list of accepted algorithms.  Must be non-empty.
            Examples: ``["HS256"]``, ``["RS256"]``, ``["RS256", "ES256"]``.
        audience: Expected value of the ``aud`` claim.  ``None`` disables
            audience verification (avoid in production).
        claim_mapping: Mapping between JWT claims and Identity fields.
        leeway_seconds: Clock skew tolerance in seconds (default 0).

    Raises:
        ValueError: If ``algorithms`` is empty (protection at construction time).
    """

    secret_or_key: str
    algorithms: list[str]
    audience: str | None = None
    claim_mapping: ClaimMapping = field(default_factory=ClaimMapping)
    leeway_seconds: int = 0
    jti_store: "JtiStore | None" = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.algorithms:
            raise ValueError(
                "The 'algorithms' parameter must be a non-empty list.  "
                "PyJWT 2.x requirement — prevents algorithm confusion attacks."
            )

    def authenticate(self, raw_token: str) -> Identity:
        """Decode and validate *raw_token*, returning a :class:`~superset_auth_kit.providers._base.Identity`.

        The token content is **never** written to logs.

        If :attr:`jti_store` is configured and the token contains a ``jti`` claim,
        anti-replay protection is activated: the ``jti`` is checked then stored.

        Args:
            raw_token: Raw JWT as a string.

        Raises:
            TokenExpiredError: The ``exp`` claim is in the past.
            TokenReplayError: The ``jti`` claim has already been consumed (anti-replay).
            TokenInvalidError: Any other PyJWT validation error.
        """
        claims = self._decode(raw_token)
        if self.jti_store is not None:
            self._check_and_record_jti(claims)
        return self._build_identity(claims)

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _decode(self, raw_token: str) -> dict[str, Any]:
        """Single centralized JWT call, compliant with PyJWT 2.x."""
        # Only exp and iat are required (RFC 7519 standards).
        # The claim mapped to 'sub' may have any name (e.g. 'user_id'):
        # _build_identity raises TokenInvalidError if the claim is missing.
        options: dict[str, Any] = {"require": ["exp", "iat"]}
        if self.audience is None:
            options["verify_aud"] = False

        try:
            return pyjwt.decode(
                raw_token,
                self.secret_or_key,
                algorithms=self.algorithms,     # mandatory in PyJWT 2.x
                audience=self.audience,
                options=options,
                leeway=self.leeway_seconds,     # direct parameter, not in options
            )
        except ExpiredSignatureError as exc:
            # Only the error type is logged — never the token content.
            logger.warning("JWT rejected: expired (%s)", type(exc).__name__)
            raise TokenExpiredError("The provided token has expired.") from exc
        except InvalidTokenError as exc:
            logger.warning("JWT rejected: invalid (%s)", type(exc).__name__)
            raise TokenInvalidError(
                f"Token validation failed: {type(exc).__name__}"
            ) from exc

    def _check_and_record_jti(self, claims: dict[str, Any]) -> None:
        """Check then record the ``jti`` claim for anti-replay protection.

        If ``jti`` is absent from the token, the check is silently skipped
        (the claim is optional per RFC 7519).

        Args:
            claims: JWT payload already validated by :meth:`_decode`.

        Raises:
            TokenReplayError: If ``jti`` is present and already known to the store.
        """
        assert self.jti_store is not None  # precondition guaranteed by the caller

        jti = claims.get("jti")
        if not jti:
            return  # jti is optional — no check if absent

        jti_str = str(jti)
        if self.jti_store.contains(jti_str):
            logger.warning("JWT rejected: jti already consumed (anti-replay)")
            raise TokenReplayError(
                f"The jti {jti_str!r} has already been used.  "
                f"This token cannot be presented a second time."
            )

        # TTL = remaining token lifetime + 30-second margin
        now = time.time()
        exp = float(claims.get("exp", now + 300))
        ttl = max(1, int(exp - now) + 30)
        self.jti_store.add(jti_str, ttl)

    def _build_identity(self, claims: dict[str, Any]) -> Identity:
        """Build an :class:`~superset_auth_kit.providers._base.Identity` from decoded claims."""
        cm = self.claim_mapping

        tenant_id = claims.get(cm.tenant_id)
        if not tenant_id or not isinstance(tenant_id, str):
            raise TokenInvalidError(
                f"Claim '{cm.tenant_id}' missing or invalid in the token."
            )

        raw_roles: Any = claims.get(cm.roles, [])
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        roles: tuple[str, ...] = tuple(str(r) for r in raw_roles if r)

        iat = datetime.fromtimestamp(float(claims["iat"]), tz=timezone.utc)
        exp = datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc)

        # Known claims are extracted; the rest constitutes the metadata.
        known: frozenset[str] = frozenset({
            cm.sub, cm.email, cm.first_name, cm.last_name,
            cm.roles, cm.tenant_id, "iat", "exp", "aud", "iss",
        })
        metadata: dict[str, Any] = {k: v for k, v in claims.items() if k not in known}

        sub_val = claims.get(cm.sub)
        if not sub_val or not isinstance(sub_val, str):
            raise TokenInvalidError(
                f"Claim '{cm.sub}' missing or invalid in the token."
            )

        return Identity(
            sub=sub_val,
            email=str(claims.get(cm.email, "")),
            first_name=str(claims.get(cm.first_name, "")),
            last_name=str(claims.get(cm.last_name, "")),
            roles=roles,
            tenant_id=tenant_id,
            issued_at=iat,
            expires_at=exp,
            metadata=metadata,
        )
