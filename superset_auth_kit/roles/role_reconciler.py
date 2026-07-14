"""Orchestrator for full bundle reconciliation (ADR-002 §3.4).

This module coordinates the three phases of the provisioning cycle:

    Phase 1 — VERSION CHECK (idempotence)
        Read from ``sak_role_version``. If the stored version == bundle.version
        and ``force=False`` → immediate skip (O(1), zero DB writes).

    Phase 2 — RESOLVE (graph materialization)
        Call ``capability_resolver.resolve``: each ``PermSpec`` is
        transformed into a FAB ``PermissionView`` object (find or create).

    Phase 3 — PROVISION (diff-set application + commit)
        Call ``role_provisioner.apply_diff`` inside a try/commit/rollback block.
        On success: ``upsert_version`` + ``session.commit()``.
        On error: ``session.rollback()`` + raise ``RoleProvisionError``.

Exclusive sovereignty (ADR-201):
    The reconciler **never** touches native roles (Gamma, Alpha, Admin,
    Public, sql_lab). It operates exclusively on roles whose name
    starts with ``sak__``.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple

from superset_auth_kit.exceptions import RoleProvisionError, VersionDowngradeError
from superset_auth_kit.roles import capability_resolver, role_provisioner
from superset_auth_kit.roles.role_provisioner import DiffResult

if TYPE_CHECKING:
    from superset_auth_kit.roles.definitions import CapabilityBundle

logger = logging.getLogger(__name__)

_SAK_ROLE_PREFIX = "sak__"


class ReconcileStatus(Enum):
    """Result of a bundle reconciliation."""

    SKIPPED = "skipped"    # Identical version, no writes
    CREATED = "created"    # Role created for the first time
    UPDATED = "updated"    # Existing role upgraded


class ReconcileResult(NamedTuple):
    """Full result of a bundle reconciliation."""

    status:     ReconcileStatus
    role_name:  str
    version:    int
    diff:       DiffResult | None  # None if SKIPPED


def reconcile_bundle(
    bundle: "CapabilityBundle",
    sm: Any,
    session: Any,
    *,
    force: bool = False,
) -> ReconcileResult:
    """Reconcile a permission bundle with the current FAB database state.

    Guarantees:
    - **Idempotence**: two successive calls without a version change
      return ``ReconcileStatus.SKIPPED`` with no DB writes.
    - **Transactionality**: on error during the diff-set, the transaction
      is rolled back → state P_n-1 is guaranteed.
    - **Sovereignty**: refuses to process any role without the ``sak__`` prefix.

    Args:
        bundle:  Bundle to provision (from ``definitions.py``).
        sm:      FAB SecurityManager (``current_app.appbuilder.sm``).
        session: Active SQLAlchemy session (``sm.get_session``).
        force:   If ``True``, bypass version checking and force a full
                 re-provisioning (useful for repair scenarios).

    Returns:
        :class:`ReconcileResult` describing the operation performed.

    Raises:
        ValueError:            If the bundle name does not start with ``sak__``.
        VersionDowngradeError: If the local version < the database version (without ``force``).
        RoleProvisionError:    If resolution or the diff-set fails.
    """
    if not bundle.role_name.startswith(_SAK_ROLE_PREFIX):
        raise ValueError(
            f"Security: role name {bundle.role_name!r} does not start with "
            f"'{_SAK_ROLE_PREFIX}'. SAK refuses to modify native Superset roles."
        )

    # ── Phase 0: ensure the versioning table exists ───────────────────────────
    role_provisioner.ensure_version_table(session)

    # ── Phase 1: version check (idempotence) ──────────────────────────────────
    stored_version = role_provisioner.get_stored_version(session, bundle.role_name)

    if not force and stored_version is not None:
        if stored_version == bundle.version:
            logger.info(
                "[AuthKit] %s v%d: already up to date — skipping.",
                bundle.role_name,
                bundle.version,
            )
            return ReconcileResult(
                status=ReconcileStatus.SKIPPED,
                role_name=bundle.role_name,
                version=bundle.version,
                diff=None,
            )

        if stored_version > bundle.version:
            raise VersionDowngradeError(
                f"Downgrade refused for {bundle.role_name!r}: "
                f"stored version={stored_version}, bundle version={bundle.version}. "
                f"Check the deployed image or use --force to override."
            )

    # ── Phase 2: resolve the permission graph ─────────────────────────────────
    logger.info(
        "[AuthKit] %s: resolving permission graph (%d permissions)…",
        bundle.role_name,
        len(bundle.permissions),
    )
    try:
        resolved_pvs = capability_resolver.resolve(bundle, sm)
    except Exception as exc:
        raise RoleProvisionError(
            f"Permission resolution failed for {bundle.role_name!r}: {exc}"
        ) from exc

    # ── Phase 3: get-or-create the FAB role ───────────────────────────────────
    role = sm.find_role(bundle.role_name)
    is_new = role is None
    if is_new:
        logger.info("[AuthKit] %s: role not found — creating.", bundle.role_name)
        role = sm.add_role(bundle.role_name)

    # ── Phase 4: apply the diff-set (transactional) ───────────────────────────
    try:
        diff = role_provisioner.apply_diff(role, resolved_pvs, sm)
        role_provisioner.upsert_version(session, bundle.role_name, bundle.version)
        session.commit()
    except Exception as exc:
        session.rollback()
        raise RoleProvisionError(
            f"Provisioning failed for {bundle.role_name!r} — rollback performed: {exc}"
        ) from exc

    status = ReconcileStatus.CREATED if is_new else ReconcileStatus.UPDATED
    logger.info(
        "[AuthKit] %s v%d: %s (+%d / -%d permissions).",
        bundle.role_name,
        bundle.version,
        status.value,
        diff.added,
        diff.removed,
    )
    return ReconcileResult(
        status=status,
        role_name=bundle.role_name,
        version=bundle.version,
        diff=diff,
    )
