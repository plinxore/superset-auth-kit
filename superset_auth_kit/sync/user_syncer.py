"""Idempotent synchronization engine between an :class:`Identity` and the FAB database.

Superset 6.1.0 / FAB 5.0.2 version constraints strictly respected:
- Only public FAB APIs are used: ``find_user``, ``add_user``,
  ``update_user``, ``find_role``, ``update_user_auth_stat``.
- ``get_or_create_user`` is **absent** from FAB 5.0.2 (verified on the runtime) —
  the find-or-create logic is implemented here explicitly.
- ``user.is_active`` is used (canonical FAB 5.x name).  ``user.active``
  is the deprecated alias maintained for backward compatibility.

The short-circuit compares the SHA-256 fingerprint of FAB-persisted attributes
stored in ``user.extra_json["authkit_fp"]`` with the one from the current identity.
On a match, ``update_user`` is not called, saving one DB write per recurring login.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from superset_auth_kit.exceptions import UserSyncError
from superset_auth_kit.providers._base import Identity
from superset_auth_kit.sync.fingerprint import IdentityFingerprint
from superset_auth_kit.sync.role_mapper import RoleMapper

logger = logging.getLogger(__name__)


@runtime_checkable
class SecurityManagerProtocol(Protocol):
    """Structural protocol for the FAB SecurityManager used by :class:`UserSyncer`.

    Avoids any direct import of ``flask_appbuilder`` or ``superset``
    so that ``superset_auth_kit`` remains installable as a standalone library.
    Only the methods actually called are declared.
    """

    def find_user(
        self,
        username: str | None = None,
        email: str | None = None,
    ) -> Any | None: ...

    def add_user(
        self,
        username: str,
        first_name: str,
        last_name: str,
        email: str,
        role: list[Any],
        password: str = "",
        hashed_password: str = "",
    ) -> Any | None: ...

    def update_user(self, user: Any) -> Any | None: ...

    def find_role(self, name: str) -> Any | None: ...

    def update_user_auth_stat(self, user: Any, success: bool = True) -> None: ...


@dataclass
class UserSyncer:
    """Synchronize an :class:`~superset_auth_kit.providers._base.Identity` with the FAB database.

    Synchronization algorithm (nominal path):

    1. Resolve FAB roles from the Identity via :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`.
    2. ``find_user(username=identity.sub)`` → FAB User object or ``None``.
    3. If ``None`` → ``add_user`` + write fingerprint + ``update_user``.
    4. If found and inactive → :class:`~superset_auth_kit.exceptions.UserSyncError`.
    5. If found and active → fingerprint comparison:
       - Match → short-circuit, no write.
       - Difference → update attributes + fingerprint + ``update_user``.
    6. ``update_user_auth_stat`` in all success cases.
    7. Return the FAB User object, ready for ``flask_login.login_user()``.

    Args:
        sm: FAB SecurityManager instance satisfying :class:`SecurityManagerProtocol`.
        role_mapper: :class:`~superset_auth_kit.sync.role_mapper.RoleMapper` instance
            configured for this deployment.
    """

    sm: SecurityManagerProtocol
    role_mapper: RoleMapper

    def sync(self, identity: Identity) -> Any:
        """Synchronize *identity* and return the FAB User object.

        Args:
            identity: Identity validated by an :class:`~superset_auth_kit.providers._base.IdentityProvider`.

        Returns:
            FAB User object (``flask_appbuilder.security.sqla.models.User``)
            ready to be passed to ``flask_login.login_user()``.

        Raises:
            UserSyncError: Inactive user, or FAB creation / update failure.
            RoleEscalationError: Propagated from :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`.
            RoleNotAllowedError: Propagated from :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`.

        Note:
            The ``user.roles`` attribute is **always** overwritten exclusively with
            the resolved SAK roles, even if the IdP fingerprint is unchanged. This
            guarantees that no native FAB role (Gamma, Alpha, …) can persist between
            logins due to silent drift (AUTH_USER_REGISTRATION_ROLE, superset init, …).
        """
        fab_roles = self._resolve_fab_roles(identity)
        user = self.sm.find_user(username=identity.sub)

        if user is None:
            user = self._create_user(identity, fab_roles)
        else:
            self._assert_active(user, identity.sub)
            user = self._update_if_changed(user, identity, fab_roles)

        self.sm.update_user_auth_stat(user, success=True)
        return user

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _resolve_fab_roles(self, identity: Identity) -> list[Any]:
        """Translate IdP roles into FAB Role objects via ``sm.find_role``."""
        superset_role_names = self.role_mapper.resolve(identity.roles)
        fab_roles: list[Any] = []
        for name in superset_role_names:
            role = self.sm.find_role(name)
            if role is None:
                raise UserSyncError(
                    f"Superset role '{name}' does not exist in the database.  "
                    f"Run 'superset init' to create default roles."
                )
            fab_roles.append(role)
        return fab_roles

    def _create_user(self, identity: Identity, fab_roles: list[Any]) -> Any:
        """Create a new FAB user and persist the initial fingerprint."""
        logger.info(
            "Creating FAB user: sub=%s… tenant=%s",
            identity.sub[:8],
            identity.tenant_id,
        )
        user = self.sm.add_user(
            username=identity.sub,
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            role=fab_roles,
            password="",    # SSO authentication only — no local login.
        )
        if not user:
            raise UserSyncError(
                f"FAB add_user returned None/False for sub={identity.sub!r}.  "
                f"Check the FAB logs (email / username uniqueness constraint?)."
            )
        # Write the fingerprint and persist via update_user.
        # add_user does not support extra_json — an update pass is required.
        fp = IdentityFingerprint.compute(identity)
        user = self._write_fingerprint_to(user, fp)
        updated = self.sm.update_user(user)
        result = updated if updated is not None else user
        logger.info("User created: sub=%s…", identity.sub[:8])
        return result

    def _update_if_changed(
        self,
        user: Any,
        identity: Identity,
        fab_roles: list[Any],
    ) -> Any:
        """Update FAB attributes if the fingerprint or roles have changed.

        The short-circuit only activates if TWO conditions are simultaneously
        true: unchanged IdP fingerprint AND identical FAB roles.
        This guarantees that a silent role drift (native FAB roles accumulated
        via AUTH_USER_REGISTRATION_ROLE or superset init) is detected
        and corrected even when the IdP identity has not changed.
        """
        new_fp = IdentityFingerprint.compute(identity)
        stored_extra = self._load_extra_json(user)
        old_fp = IdentityFingerprint.from_user_extra_json(stored_extra)

        # Structural role comparison by name.
        # getattr(..., "name", None) is used to avoid any dependency
        # on FAB internals (the Role object is opaque in the Protocol).
        current_role_names = frozenset(
            getattr(r, "name", None) for r in getattr(user, "roles", [])
        )
        target_role_names = frozenset(getattr(r, "name", None) for r in fab_roles)
        roles_drifted = current_role_names != target_role_names

        if old_fp == new_fp and not roles_drifted:
            logger.debug(
                "Fingerprint and roles unchanged for sub=%s… — DB write skipped.",
                identity.sub[:8],
            )
            return user

        if roles_drifted:
            logger.warning(
                "SECURITY — Role drift detected for sub=%s…: "
                "DB roles=%s ≠ SAK roles=%s. Forcing correction.",
                identity.sub[:8],
                sorted(str(n) for n in current_role_names),
                sorted(str(n) for n in target_role_names),
            )
        else:
            logger.info(
                "Fingerprint changed for sub=%s… — synchronizing attributes.",
                identity.sub[:8],
            )

        user.first_name = identity.first_name
        user.last_name = identity.last_name
        user.email = identity.email
        user.roles = fab_roles  # Exclusive overwrite — SAK sovereignty.
        user = self._write_fingerprint_to(user, new_fp)
        updated = self.sm.update_user(user)
        # update_user must return the User object on success.
        # Both None (silent failure / unexpected void return) and False (explicit
        # FAB DB error) are treated as failures and raise UserSyncError.
        if updated is None or updated is False:
            raise UserSyncError(
                f"FAB update_user failed for sub={identity.sub!r}."
            )
        logger.info("User updated: sub=%s…", identity.sub[:8])
        return updated

    def _write_fingerprint_to(self, user: Any, fingerprint: str) -> Any:
        """Write the fingerprint into ``user.extra_json`` (in-memory, no commit)."""
        existing = self._load_extra_json(user)
        existing["authkit_fp"] = fingerprint
        user.extra_json = existing
        return user

    @staticmethod
    def _load_extra_json(user: Any) -> dict[str, Any]:
        """Read and deserialize ``user.extra_json`` robustly.

        FAB may store ``extra_json`` either as a ``dict`` (if the ORM has
        deserialized it) or as a JSON ``str`` (raw read from some backends).
        Both cases are handled.
        """
        raw = getattr(user, "extra_json", None)
        if raw is None:
            return {}
        if isinstance(raw, dict):
            return dict(raw)
        if isinstance(raw, str):
            try:
                result = json.loads(raw)
                return result if isinstance(result, dict) else {}
            except (ValueError, TypeError):
                return {}
        return {}

    @staticmethod
    def _assert_active(user: Any, sub: str) -> None:
        """Raise :class:`~superset_auth_kit.exceptions.UserSyncError` if the user is inactive.

        Uses ``user.is_active`` (canonical FAB 5.x).  The deprecated alias
        ``user.active`` is used as a fallback if ``is_active`` is absent.
        """
        is_active = getattr(user, "is_active", getattr(user, "active", True))
        if not is_active:
            raise UserSyncError(
                f"User sub={sub!r} exists but is marked inactive in Superset."
            )
