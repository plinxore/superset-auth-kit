"""Phase 2 of reconciliation: resolving PermSpec objects into FAB PermissionView objects.

The resolver is **pure**: it does not modify any role, does not commit any transaction,
and has no knowledge of the ``sak_role_version`` table. Its sole purpose is to
materialize the abstract graph (``frozenset[PermSpec]``) into concrete FAB objects.

Resolution strategy (ADR-202):
    For each ``PermSpec(action, view_menu)``:
    1. ``sm.find_permission_view_menu(action, view_menu)`` → look up in the database.
    2. If ``None`` → ``sm.add_permission_view_menu(action, view_menu)`` → create.

    Creation is idempotent: if the permission already exists in FAB (because
    Superset registered it during init), ``find`` will find it.
    If it does not exist yet (permission declared before Superset loads the
    corresponding view), it is created as an orphan entry in FAB —
    which is harmless and automatically corrected on the next ``superset init``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from superset_auth_kit.roles.definitions import CapabilityBundle


def resolve(bundle: "CapabilityBundle", sm: Any) -> frozenset[Any]:
    """Materialize the ``PermSpec`` objects of a bundle into FAB ``PermissionView`` objects.

    This function is the **only** one that calls ``sm.find_permission_view_menu``
    and ``sm.add_permission_view_menu`` — all other layers operate on the
    objects returned here.

    Args:
        bundle: Permission bundle to materialize.
        sm:     FAB/Superset SecurityManager (``current_app.appbuilder.sm``).
                Must expose ``find_permission_view_menu`` and
                ``add_permission_view_menu``.

    Returns:
        ``frozenset`` of FAB ``PermissionView`` objects ready to be compared
        with the role's current permissions (diff-set phase of the provisioner).

    Note:
        This function does not open a transaction — the caller (reconciler)
        is responsible for transaction management.
    """
    resolved: set[Any] = set()

    for perm_spec in bundle.permissions:
        pv = sm.find_permission_view_menu(perm_spec.action, perm_spec.view_menu)
        if pv is None:
            pv = sm.add_permission_view_menu(perm_spec.action, perm_spec.view_menu)
        resolved.add(pv)

    return frozenset(resolved)


def check_compat(bundle: "CapabilityBundle", sm: Any) -> list[tuple[str, str]]:
    """Check which permissions in the bundle do not exist in the FAB registry.

    Unlike ``resolve``, this function **never** calls ``add_permission_view_menu``
    — it is strictly read-only.

    Used by ``superset authkit check-compat`` to detect API drift
    when upgrading Superset.

    Args:
        bundle: Bundle to check.
        sm:     FAB SecurityManager (read-only).

    Returns:
        List of ``(action, view_menu)`` tuples absent from the FAB registry.
        Empty list → bundle is fully compatible with the installed version.
    """
    missing: list[tuple[str, str]] = []

    for perm_spec in sorted(bundle.permissions):
        pv = sm.find_permission_view_menu(perm_spec.action, perm_spec.view_menu)
        if pv is None:
            missing.append((perm_spec.action, perm_spec.view_menu))

    return missing
