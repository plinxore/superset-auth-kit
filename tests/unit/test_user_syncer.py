"""Unit tests — UserSyncer (find-or-create, fingerprint, idempotence)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call

import pytest

from superset_auth_kit.exceptions import UserSyncError
from superset_auth_kit.providers._base import Identity
from superset_auth_kit.sync.fingerprint import IdentityFingerprint
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.sync.user_syncer import UserSyncer

# ── Helpers ──────────────────────────────────────────────────────────────────

_NOW = datetime.now(timezone.utc)
_EXP = _NOW + timedelta(hours=1)


def _identity(
    sub: str = "user-123",
    email: str = "test@example.com",
    first_name: str = "Test",
    last_name: str = "User",
    roles: tuple[str, ...] = ("viewer",),
    tenant_id: str = "tenant-1",
) -> Identity:
    return Identity(
        sub=sub,
        email=email,
        first_name=first_name,
        last_name=last_name,
        roles=roles,
        tenant_id=tenant_id,
        issued_at=_NOW,
        expires_at=_EXP,
    )


def _mock_role(name: str = "Gamma") -> MagicMock:
    role = MagicMock()
    role.name = name
    return role


def _mapper() -> RoleMapper:
    return RoleMapper(
        mapping={"viewer": "Gamma"},
        allowed_roles=frozenset({"Gamma"}),
    )


def _make_sm(existing_user: object | None = None, role_name: str = "Gamma") -> MagicMock:
    sm = MagicMock()
    sm.find_user.return_value = existing_user
    sm.find_role.return_value = _mock_role(role_name)
    return sm


def _active_user(
    extra_json: dict | str | None = None,
    roles: list[MagicMock] | None = None,
) -> MagicMock:
    user = MagicMock()
    user.is_active = True
    user.extra_json = extra_json
    # Roles must be a real list — MagicMock iteration returns [] by default,
    # which would always show as "no current roles" and trigger a drift write.
    user.roles = roles if roles is not None else []
    return user


# ── New user creation ─────────────────────────────────────────────────────────


def test_create_new_user_calls_add_user() -> None:
    sm = _make_sm(existing_user=None)
    created = _active_user()
    sm.add_user.return_value = created
    sm.update_user.return_value = created

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    result = syncer.sync(_identity())

    sm.add_user.assert_called_once()
    call_kwargs = sm.add_user.call_args
    assert call_kwargs.kwargs["username"] == "user-123"
    assert call_kwargs.kwargs["email"] == "test@example.com"


def test_create_new_user_writes_fingerprint() -> None:
    """After add_user, the fingerprint is persisted via an update_user call."""
    sm = _make_sm(existing_user=None)
    created = _active_user()
    sm.add_user.return_value = created
    sm.update_user.return_value = created

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(_identity())

    sm.update_user.assert_called_once()


def test_create_user_updates_auth_stat() -> None:
    sm = _make_sm(existing_user=None)
    created = _active_user()
    sm.add_user.return_value = created
    sm.update_user.return_value = created

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(_identity())

    sm.update_user_auth_stat.assert_called_once()


def test_add_user_returns_none_raises_user_sync_error() -> None:
    sm = _make_sm(existing_user=None)
    sm.add_user.return_value = None

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    with pytest.raises(UserSyncError, match="add_user"):
        syncer.sync(_identity())


# ── Fingerprint short-circuit (idempotence) ───────────────────────────────────


def test_fingerprint_unchanged_skips_update_user() -> None:
    identity = _identity()
    fp = IdentityFingerprint.compute(identity)

    # Roles must match the target (resolved by _mapper) for the short-circuit to fire.
    # _mapper() resolves "viewer" → "Gamma"; sm.find_role returns _mock_role("Gamma").
    gamma = _mock_role("Gamma")
    user = _active_user(extra_json={"authkit_fp": fp}, roles=[gamma])
    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = gamma

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_not_called()
    sm.update_user_auth_stat.assert_called_once()


def test_fingerprint_changed_calls_update_user() -> None:
    identity = _identity()

    user = _active_user(extra_json={"authkit_fp": "old-fp-totalement-different"})
    sm = _make_sm(existing_user=user)
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_called_once()


def test_fingerprint_changes_update_attributes() -> None:
    """After a fingerprint change, FAB attributes are updated."""
    old_identity = _identity(first_name="OldFirst", last_name="OldLast")
    new_identity = _identity(first_name="NewFirst", last_name="NewLast")
    old_fp = IdentityFingerprint.compute(old_identity)

    user = _active_user(extra_json={"authkit_fp": old_fp})
    sm = _make_sm(existing_user=user)
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(new_identity)

    # The mock user's attributes were modified before the update_user call
    assert user.first_name == "NewFirst"
    assert user.last_name == "NewLast"


# ── extra_json as JSON string (legacy SQLAlchemy backend) ─────────────────────


def test_extra_json_as_json_string_short_circuits() -> None:
    identity = _identity()
    fp = IdentityFingerprint.compute(identity)

    gamma = _mock_role("Gamma")
    user = _active_user(extra_json=json.dumps({"authkit_fp": fp}), roles=[gamma])
    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = gamma

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_not_called()


def test_extra_json_invalid_string_treated_as_empty() -> None:
    """extra_json that is not valid JSON is treated as absent."""
    identity = _identity()

    user = _active_user(extra_json="not-valid-json{{{")
    sm = _make_sm(existing_user=user)
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_called_once()  # different fp → update


def test_extra_json_none_treated_as_empty() -> None:
    identity = _identity()

    user = _active_user(extra_json=None)
    sm = _make_sm(existing_user=user)
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_called_once()


# ── Inactive user ─────────────────────────────────────────────────────────────


def test_inactive_user_is_active_false_raises() -> None:
    user = MagicMock()
    user.is_active = False
    sm = _make_sm(existing_user=user)

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    with pytest.raises(UserSyncError, match="inactive"):
        syncer.sync(_identity())


def test_inactive_user_active_alias_raises() -> None:
    """FAB legacy: 'active' instead of 'is_active'."""
    user = MagicMock(spec=[])  # spec=[] → no native is_active
    user.active = False  # deprecated FAB alias
    sm = _make_sm(existing_user=user)

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    with pytest.raises(UserSyncError):
        syncer.sync(_identity())


# ── FAB role resolution ───────────────────────────────────────────────────────


def test_role_not_in_fab_raises_user_sync_error() -> None:
    """If find_role returns None, the role does not exist in the database → UserSyncError."""
    sm = _make_sm(existing_user=None)
    sm.find_role.return_value = None  # role unknown to FAB

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    with pytest.raises(UserSyncError, match="does not exist"):
        syncer.sync(_identity())


def test_update_user_returns_none_raises_user_sync_error() -> None:
    identity = _identity()
    user = _active_user(extra_json={"authkit_fp": "old-fp"})
    sm = _make_sm(existing_user=user)
    sm.update_user.return_value = None  # FAB fails silently

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    with pytest.raises(UserSyncError, match="update_user"):
        syncer.sync(identity)


# ── SECURITY: Role drift ──────────────────────────────────────────────────────


def test_role_drift_with_unchanged_fingerprint_triggers_update_user() -> None:
    """A user whose IdP fingerprint is stable but whose FAB roles have drifted
    (e.g. native Gamma role injected by AUTH_USER_REGISTRATION_ROLE)
    MUST trigger an update_user to correct the roles.

    This is the central security bug: without this test, the fingerprint short-circuit
    would let native roles persist between two logins.
    """
    identity = _identity()
    fp = IdentityFingerprint.compute(identity)

    # User exists with correct fp but WRONG roles (native "Alpha" instead of "Gamma").
    native_alpha = _mock_role("Alpha")
    user = _active_user(extra_json={"authkit_fp": fp}, roles=[native_alpha])

    gamma = _mock_role("Gamma")
    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = gamma
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    # Drift detected → DB write must happen despite unchanged fingerprint.
    sm.update_user.assert_called_once()


def test_role_drift_overwrites_native_roles_exclusively() -> None:
    """After drift detection, user.roles is overwritten exclusively with
    SAK roles — no accumulation with existing native roles."""
    identity = _identity()
    fp = IdentityFingerprint.compute(identity)

    # Simulate FAB having assigned both a native role AND an extra drift role.
    native_gamma = _mock_role("Gamma")
    native_alpha = _mock_role("Alpha")
    user = _active_user(
        extra_json={"authkit_fp": fp},
        roles=[native_gamma, native_alpha],  # extra native role from drift
    )

    target_gamma = _mock_role("Gamma")
    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = target_gamma
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    # user.roles must be EXACTLY [target_gamma] — not [gamma, alpha, gamma].
    assert user.roles == [target_gamma]


def test_new_user_receives_only_sak_roles_not_native_defaults() -> None:
    """A newly created user receives EXACTLY the resolved SAK roles.
    No additional native FAB roles."""
    sm = _make_sm(existing_user=None)

    gamma = _mock_role("Gamma")
    sm.find_role.return_value = gamma

    created = _active_user(roles=[gamma])
    sm.add_user.return_value = created
    sm.update_user.return_value = created

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(_identity())

    # add_user must be called with role=[gamma] only.
    add_call_kwargs = sm.add_user.call_args.kwargs
    assert add_call_kwargs["role"] == [gamma]


def test_role_drift_accumulation_scenario_gamma_alpha_corrected_to_gamma_only() -> None:
    """Real scenario: user created by superset init with Gamma+Alpha,
    or AUTH_USER_REGISTRATION_ROLE='Alpha'. On the next SSO login, only
    Gamma should remain — Alpha must be removed by exclusive overwrite."""
    identity = _identity(roles=("viewer",))
    fp = IdentityFingerprint.compute(identity)

    gamma = _mock_role("Gamma")
    alpha = _mock_role("Alpha")

    # DB state: user has both Gamma and Alpha (drift from FAB default).
    user = _active_user(extra_json={"authkit_fp": fp}, roles=[gamma, alpha])

    target_gamma = _mock_role("Gamma")
    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = target_gamma
    sm.update_user.return_value = user

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    # After sync: only the SAK-resolved role (Gamma) remains.
    sm.update_user.assert_called_once()
    assert user.roles == [target_gamma]


def test_no_spurious_write_when_roles_and_fingerprint_both_match() -> None:
    """The short-circuit saves a DB write when both the fingerprint AND roles
    are unchanged — no performance regression."""
    identity = _identity()
    fp = IdentityFingerprint.compute(identity)

    gamma = _mock_role("Gamma")
    # DB state is exactly what SAK expects: correct fp AND correct roles.
    user = _active_user(extra_json={"authkit_fp": fp}, roles=[gamma])

    sm = _make_sm(existing_user=user)
    sm.find_role.return_value = gamma  # resolve returns same object by name

    syncer = UserSyncer(sm=sm, role_mapper=_mapper())
    syncer.sync(identity)

    sm.update_user.assert_not_called()
    sm.update_user_auth_stat.assert_called_once()
