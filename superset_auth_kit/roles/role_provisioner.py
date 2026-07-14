"""Phase 3 of reconciliation: applying the diff-set and managing sak_role_version.

This module is responsible for TWO operations:
1. DDL — Creating the ``sak_role_version`` table if it does not exist.
2. DML — Reading / writing versions + applying the FAB diff-set.

The ``sak_role_version`` table is the idempotence mechanism:

    CREATE TABLE IF NOT EXISTS sak_role_version (
        role_name       VARCHAR(64)  PRIMARY KEY,
        bundle_version  INTEGER      NOT NULL,
        provisioned_at  TIMESTAMP    NOT NULL DEFAULT NOW()
    )

Transactional architecture (ADR-202):
    - The provisioner never commits by itself.
    - The reconciler calls it inside a try/except → commit or rollback.
    - This guarantees that a partial failure (e.g. add_permission_role on perm 30/55)
      rolls back all modifications and leaves the database in the previous state
      (state P_n-1, not P_partial).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, NamedTuple

from sqlalchemy import text

if TYPE_CHECKING:
    from superset_auth_kit.roles.definitions import CapabilityBundle

_DDL_CREATE_VERSION_TABLE = text("""
    CREATE TABLE IF NOT EXISTS sak_role_version (
        role_name       VARCHAR(64)  NOT NULL,
        bundle_version  INTEGER      NOT NULL,
        provisioned_at  TIMESTAMP    NOT NULL,
        PRIMARY KEY (role_name)
    )
""")

_SQL_GET_VERSION = text(
    "SELECT bundle_version FROM sak_role_version WHERE role_name = :role_name"
)
_SQL_UPSERT_VERSION = text("""
    INSERT INTO sak_role_version (role_name, bundle_version, provisioned_at)
    VALUES (:role_name, :bundle_version, :provisioned_at)
    ON CONFLICT (role_name)
    DO UPDATE SET bundle_version = :bundle_version,
                  provisioned_at = :provisioned_at
""")


class DiffResult(NamedTuple):
    """Result of applying the FAB diff-set."""

    added:   int  # Number of permissions added to the role
    removed: int  # Number of permissions removed from the role


def ensure_version_table(session: Any) -> None:
    """Create the ``sak_role_version`` table if it does not yet exist.

    Idempotent (``CREATE TABLE IF NOT EXISTS``). Call at the start of each
    reconciliation to guarantee the table exists even on the first run.

    Args:
        session: Active SQLAlchemy session (provided by the reconciler).
    """
    session.execute(_DDL_CREATE_VERSION_TABLE)


def get_stored_version(session: Any, role_name: str) -> int | None:
    """Read the version stored in ``sak_role_version`` for a given role.

    Args:
        session:   Active SQLAlchemy session.
        role_name: FAB role name (e.g. ``"sak__dashboard_consumer"``).

    Returns:
        Integer version if the role has already been provisioned, ``None`` otherwise.
    """
    result = session.execute(_SQL_GET_VERSION, {"role_name": role_name})
    row = result.fetchone()
    return int(row[0]) if row is not None else None


def upsert_version(session: Any, role_name: str, version: int) -> None:
    """Write or update the version in ``sak_role_version``.

    The operation is a PostgreSQL UPSERT (``ON CONFLICT DO UPDATE``).
    Call AFTER successfully applying the diff-set, BEFORE committing.

    Args:
        session:   Active SQLAlchemy session.
        role_name: FAB role name.
        version:   Version number of the provisioned bundle.
    """
    session.execute(
        _SQL_UPSERT_VERSION,
        {
            "role_name":      role_name,
            "bundle_version": version,
            "provisioned_at": datetime.now(timezone.utc),
        },
    )


def apply_diff(
    role: Any,
    target_pvs: frozenset[Any],
    sm: Any,
) -> DiffResult:
    """Apply the diff-set between the target permissions and the current permissions.

    Algorithm (ADR-202 §3.3):
        current = {current PermissionView objects of the role in the database}
        to_add  = target_pvs - current  → sm.add_permission_role
        to_remove = current - target_pvs → sm.del_permission_role

    Args:
        role:       FAB ``ab_role`` object (must have an ``id``).
        target_pvs: Target graph (result of ``capability_resolver.resolve``).
        sm:         FAB SecurityManager.

    Returns:
        :class:`DiffResult` with ``added`` and ``removed`` counts.

    Note:
        This function does not commit — the caller manages the transaction.
    """
    current_pvs: frozenset[Any] = frozenset(sm.get_db_role_permissions(role.id))

    to_add    = target_pvs - current_pvs
    to_remove = current_pvs - target_pvs

    for pv in to_add:
        sm.add_permission_role(role, pv)

    for pv in to_remove:
        sm.del_permission_role(role, pv)

    return DiffResult(added=len(to_add), removed=len(to_remove))
