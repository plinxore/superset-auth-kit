"""Resolution of IdP roles into Superset/FAB roles.

Two layers of protection against privilege escalation:
1. **At construction time**: static validation of the mapping and the whitelist.
2. **At resolution time**: dynamic check of each resolved role
   (defense in depth against runtime configuration injection).

The check is case-insensitive (``"admin"``, ``"Admin"``,
``"ADMIN"`` are all forbidden by default).

``allow_native_admin=True`` explicitly lifts this restriction to allow
mapping an IdP role to the native FAB ``Admin`` role. Use only for
platform super-admins (e.g. ``platform_admin`` → ``sak__admin``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from superset_auth_kit.exceptions import RoleEscalationError, RoleNotAllowedError

logger = logging.getLogger(__name__)

# Forbidden substrings in any Superset role name assigned via SSO.
# Comparison is always performed after ``.lower()``.
_FORBIDDEN_SUBSTRINGS: frozenset[str] = frozenset({"admin"})

# Native Superset FAB role allowed when allow_native_admin=True.
_NATIVE_ADMIN_ROLE = "admin"


def _is_forbidden(role_name: str, *, allow_admin: bool = False) -> bool:
    """Return ``True`` if *role_name* contains a forbidden substring.

    If *allow_admin* is ``True``, the ``Admin`` role (case-insensitive)
    is permitted even though it contains the substring "admin".
    """
    lowered = role_name.lower()
    if allow_admin and lowered == _NATIVE_ADMIN_ROLE:
        return False
    return any(forbidden in lowered for forbidden in _FORBIDDEN_SUBSTRINGS)


@dataclass
class RoleMapper:
    """Translate IdP role names into Superset role names.

    Args:
        mapping: Dictionary ``{idp_name: superset_name}``.
            Example: ``{"app_viewer": "Gamma", "app_analyst": "Alpha"}``.
        allowed_roles: Set of IdP role names permitted via SSO.
            Any resolution toward a role outside this set raises
            :class:`~superset_auth_kit.exceptions.RoleNotAllowedError`.
        default_roles: Roles applied when no IdP role matches the mapping.
            Must be a subset of ``allowed_roles``.
        allow_native_admin: If ``True``, permits mapping to the native FAB
            ``Admin`` role. Reserved for platform super-admins. ``False`` by default.

    Raises:
        RoleEscalationError: At construction time, if ``mapping`` or ``allowed_roles``
            contain a role with a forbidden substring (unless
            ``allow_native_admin=True`` for the exact ``Admin`` target).
    """

    mapping: dict[str, "str | list[str]"]
    allowed_roles: frozenset[str]
    default_roles: tuple[str, ...] = field(default_factory=tuple)
    allow_native_admin: bool = False

    def __post_init__(self) -> None:
        # Static mapping validation at construction time — fail-fast.
        # Values may be a str (one-to-one) or list[str] (one-to-many).
        for idp_role, target in self.mapping.items():
            targets = [target] if isinstance(target, str) else target
            for superset_role in targets:
                if _is_forbidden(superset_role, allow_admin=self.allow_native_admin):
                    raise RoleEscalationError(
                        f"Invalid configuration: mapping '{idp_role}' → '{superset_role}' "
                        f"targets a forbidden privileged role.  "
                        f"Remove it from the mapping or pass allow_native_admin=True."
                    )
        # Note: allowed_roles contains IdP role names (JWT claims),
        # not FAB Superset roles. The "admin" check does not apply here —
        # security is enforced through the mapping values above.
        for role in self.default_roles:
            if _is_forbidden(role, allow_admin=False):
                raise RoleEscalationError(
                    f"Invalid configuration: '{role}' is in 'default_roles' "
                    f"but contains a forbidden substring ('admin')."
                )

    def resolve(self, idp_roles: tuple[str, ...]) -> tuple[str, ...]:
        """Resolve *idp_roles* into Superset role names.

        Args:
            idp_roles: Tuple of role names as received from the identity provider.

        Returns:
            Tuple of Superset role names, deduplicated, in stable order.

        Raises:
            RoleEscalationError: If a resolved role contains a forbidden substring
                (defense-in-depth layer, runtime check).
            RoleNotAllowedError: If a resolved role is not in ``allowed_roles``.
        """
        resolved: list[str] = []

        for idp_role in idp_roles:
            target = self.mapping.get(idp_role)
            if target is None:
                logger.debug("IdP role '%s' not found in mapping — ignored.", idp_role)
                continue
            targets = [target] if isinstance(target, str) else target
            for superset_role in targets:
                self._assert_safe(superset_role)
                resolved.append(superset_role)

        if not resolved:
            logger.debug(
                "No matching IdP roles; applying default roles: %s",
                self.default_roles,
            )
            for role in self.default_roles:
                self._assert_safe(role)
            resolved = list(self.default_roles)

        # dict.fromkeys preserves insertion order while deduplicating.
        return tuple(dict.fromkeys(resolved))

    def _assert_safe(self, role_name: str) -> None:
        """Raise an exception if *role_name* is forbidden or outside the whitelist."""
        is_native_admin = role_name.lower() == _NATIVE_ADMIN_ROLE
        if _is_forbidden(role_name, allow_admin=self.allow_native_admin):
            logger.critical(
                "SECURITY — Privilege escalation attempt toward '%s' blocked.",
                role_name,
            )
            raise RoleEscalationError(
                f"Assigning role '{role_name}' is forbidden via SSO."
            )
        # The native FAB "Admin" role does not appear in allowed_roles (which contains
        # IdP names) — skip the check when allow_native_admin=True.
        if not (is_native_admin and self.allow_native_admin) and role_name not in self.allowed_roles:
            raise RoleNotAllowedError(
                f"Role '{role_name}' is not in the 'allowed_roles' whitelist."
            )
