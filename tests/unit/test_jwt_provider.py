"""Unit tests — JwtProvider (HS256, RS256, expiry, jti replay)."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from superset_auth_kit.exceptions import TokenExpiredError, TokenInvalidError, TokenReplayError
from superset_auth_kit.providers.jwt import ClaimMapping, JwtProvider
from superset_auth_kit.replay.blocklist import InMemoryJtiStore

# ── Helpers ──────────────────────────────────────────────────────────────────

HS256_SECRET = "test-secret-hs256-suffisamment-long"
ALGORITHMS_HS = ["HS256"]


def _hs256_token(
    *,
    sub: str = "user-abc-123",
    email: str = "alice@example.com",
    given_name: str = "Alice",
    family_name: str = "Smith",
    roles: list[str] | None = None,
    tenant_id: str = "tenant-1",
    exp_delta: int = 300,
    include_jti: bool = False,
    extra: dict | None = None,
    secret: str = HS256_SECRET,
) -> str:
    now = int(time.time())
    claims: dict = {
        "sub": sub,
        "email": email,
        "given_name": given_name,
        "family_name": family_name,
        "roles": roles if roles is not None else ["viewer"],
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + exp_delta,
    }
    if include_jti:
        claims["jti"] = str(uuid.uuid4())
    if extra:
        claims.update(extra)
    return pyjwt.encode(claims, secret, algorithm="HS256")


def _rsa_keypair() -> tuple[bytes, bytes]:
    """Generate a 2048-bit RSA key pair for RS256 tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ── Construction ─────────────────────────────────────────────────────────────


def test_empty_algorithms_raises_at_construction() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        JwtProvider(secret_or_key=HS256_SECRET, algorithms=[])


# ── HS256 decoding ────────────────────────────────────────────────────────────


def test_hs256_valid_token_fields() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    identity = provider.authenticate(_hs256_token())

    assert identity.sub == "user-abc-123"
    assert identity.email == "alice@example.com"
    assert identity.first_name == "Alice"
    assert identity.last_name == "Smith"
    assert identity.roles == ("viewer",)
    assert identity.tenant_id == "tenant-1"
    assert isinstance(identity.issued_at, datetime)
    assert isinstance(identity.expires_at, datetime)
    assert identity.issued_at.tzinfo == timezone.utc
    assert identity.expires_at.tzinfo == timezone.utc


def test_hs256_multiple_roles() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    identity = provider.authenticate(_hs256_token(roles=["viewer", "analyst"]))
    assert identity.roles == ("viewer", "analyst")


def test_hs256_roles_as_single_string() -> None:
    """A 'roles' claim that is a string rather than a list is tolerated."""
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token(extra={"roles": "viewer"})
    identity = provider.authenticate(token)
    assert identity.roles == ("viewer",)


def test_hs256_extra_claims_in_metadata() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token(extra={"custom_claim": "custom_value"})
    identity = provider.authenticate(token)
    assert identity.metadata.get("custom_claim") == "custom_value"


# ── RS256 decoding ────────────────────────────────────────────────────────────


def test_rs256_valid_token() -> None:
    private_pem, public_pem = _rsa_keypair()

    now = int(time.time())
    claims = {
        "sub": "user-rs256",
        "email": "rsa@example.com",
        "given_name": "Bob",
        "family_name": "RSA",
        "roles": ["analyst"],
        "tenant_id": "tenant-rsa",
        "iat": now,
        "exp": now + 300,
    }
    token = pyjwt.encode(claims, private_pem, algorithm="RS256")
    provider = JwtProvider(
        secret_or_key=public_pem.decode(),
        algorithms=["RS256"],
    )
    identity = provider.authenticate(token)
    assert identity.sub == "user-rs256"
    assert identity.tenant_id == "tenant-rsa"


def test_rs256_rejects_hs256_token() -> None:
    """An HS256 token presented to an RS256 provider must be rejected."""
    _, public_pem = _rsa_keypair()
    provider = JwtProvider(secret_or_key=public_pem.decode(), algorithms=["RS256"])
    hs_token = _hs256_token()

    with pytest.raises(TokenInvalidError):
        provider.authenticate(hs_token)


# ── Expiration handling ───────────────────────────────────────────────────────


def test_expired_token_raises_token_expired_error() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token(exp_delta=-10)
    with pytest.raises(TokenExpiredError):
        provider.authenticate(token)


def test_expired_token_not_confused_with_invalid() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token(exp_delta=-10)
    with pytest.raises(TokenExpiredError):
        provider.authenticate(token)
    # Ensure TokenExpiredError is NOT directly TokenInvalidError
    # (but it is a subclass via AuthKitError)
    try:
        provider.authenticate(token)
    except TokenExpiredError:
        pass
    except TokenInvalidError:
        pytest.fail("TokenExpiredError must not be caught as TokenInvalidError alone")


def test_leeway_accepts_slightly_expired_token() -> None:
    provider = JwtProvider(
        secret_or_key=HS256_SECRET,
        algorithms=ALGORITHMS_HS,
        leeway_seconds=15,
    )
    token = _hs256_token(exp_delta=-5)
    identity = provider.authenticate(token)
    assert identity.sub == "user-abc-123"


# ── Invalid signature ─────────────────────────────────────────────────────────


def test_wrong_secret_raises_token_invalid_error() -> None:
    provider = JwtProvider(secret_or_key="wrong-secret", algorithms=ALGORITHMS_HS)
    token = _hs256_token()
    with pytest.raises(TokenInvalidError):
        provider.authenticate(token)


def test_tampered_payload_raises_token_invalid_error() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token()
    # Inject a character into the payload (middle part of the JWT)
    parts = token.split(".")
    parts[1] = parts[1][:-2] + "AA"
    with pytest.raises(TokenInvalidError):
        provider.authenticate(".".join(parts))


# ── Missing claims ────────────────────────────────────────────────────────────


def test_missing_tenant_id_raises() -> None:
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    now = int(time.time())
    claims = {
        "sub": "user", "email": "u@e.com", "given_name": "A", "family_name": "B",
        "roles": ["viewer"], "iat": now, "exp": now + 300,
    }
    token = pyjwt.encode(claims, HS256_SECRET, algorithm="HS256")
    with pytest.raises(TokenInvalidError, match="tenant_id"):
        provider.authenticate(token)


def test_custom_claim_mapping() -> None:
    """Custom ClaimMapping for an IdP with different claim names."""
    provider = JwtProvider(
        secret_or_key=HS256_SECRET,
        algorithms=ALGORITHMS_HS,
        claim_mapping=ClaimMapping(
            sub="user_id",
            email="mail",
            first_name="prenom",
            last_name="nom",
            roles="permissions",
            tenant_id="org_id",
        ),
    )
    now = int(time.time())
    claims = {
        "user_id": "uid-789",
        "mail": "custom@example.com",
        "prenom": "Marie",
        "nom": "Curie",
        "permissions": ["scientist"],
        "org_id": "labo-paris",
        "iat": now,
        "exp": now + 300,
    }
    token = pyjwt.encode(claims, HS256_SECRET, algorithm="HS256")
    identity = provider.authenticate(token)
    assert identity.sub == "uid-789"
    assert identity.email == "custom@example.com"
    assert identity.first_name == "Marie"
    assert identity.tenant_id == "labo-paris"


# ── Anti-replay protection (jti) ─────────────────────────────────────────────


def test_jti_first_call_succeeds() -> None:
    store = InMemoryJtiStore()
    provider = JwtProvider(
        secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS, jti_store=store
    )
    token = _hs256_token(include_jti=True)
    identity = provider.authenticate(token)
    assert identity.sub == "user-abc-123"


def test_jti_second_call_raises_token_replay_error() -> None:
    store = InMemoryJtiStore()
    provider = JwtProvider(
        secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS, jti_store=store
    )
    token = _hs256_token(include_jti=True)
    provider.authenticate(token)  # 1st presentation — OK
    with pytest.raises(TokenReplayError):
        provider.authenticate(token)  # 2nd — blocked


def test_jti_without_store_allows_multiple_calls() -> None:
    """Without a configured jti_store, anti-replay protection is inactive."""
    provider = JwtProvider(secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS)
    token = _hs256_token(include_jti=True)
    provider.authenticate(token)
    provider.authenticate(token)  # must succeed — no blocklist


def test_jti_token_without_jti_claim_not_blocked() -> None:
    """A token without a 'jti' claim is not blocked even if the store is configured."""
    store = InMemoryJtiStore()
    provider = JwtProvider(
        secret_or_key=HS256_SECRET, algorithms=ALGORITHMS_HS, jti_store=store
    )
    token = _hs256_token(include_jti=False)
    provider.authenticate(token)
    provider.authenticate(token)  # no jti → no blocklist check


def test_token_replay_error_is_subclass_of_token_invalid_error() -> None:
    """TokenReplayError must be catchable as TokenInvalidError."""
    exc = TokenReplayError("test")
    assert isinstance(exc, TokenInvalidError)
