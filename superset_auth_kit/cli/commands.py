"""Flask/Superset CLI commands for the superset-auth-kit package.

Registered via the ``flask.commands`` entry-point (pyproject.toml):

    [project.entry-points."flask.commands"]
    authkit = "superset_auth_kit.cli.commands:authkit_cli"

After installation (``pip install -e .``), commands are available via:

    superset authkit provision-roles [--bundle <key>]... [--force] [--dry-run]
    superset authkit check-compat    [--bundle <key>]...

Typical usage in a CI/CD pipeline or a Kubernetes initContainer:

    # Provision all bundles (idempotent)
    superset authkit provision-roles

    # Check API compatibility before deploying
    superset authkit check-compat || exit 1

    # Force re-provisioning after a permissions fix
    superset authkit provision-roles --force

    # Provision only the dashboard_consumer bundle
    superset authkit provision-roles --bundle dashboard_consumer
"""

from __future__ import annotations

import sys
import logging

import click
from flask.cli import AppGroup, with_appcontext

from superset_auth_kit.roles.definitions import ALL_BUNDLES, CapabilityBundle
from superset_auth_kit.exceptions import (
    RoleProvisionError,
    VersionDowngradeError,
)

logger = logging.getLogger(__name__)

# Root CLI group — registered via the "flask.commands" entry-point
authkit_cli = AppGroup(
    "authkit",
    help="superset-auth-kit administration commands (provisioning, compatibility).",
)


def _resolve_bundles(bundle_keys: tuple[str, ...]) -> list[CapabilityBundle]:
    """Translate CLI keys into CapabilityBundle objects, with validation."""
    if not bundle_keys:
        return list(ALL_BUNDLES.values())

    resolved = []
    for key in bundle_keys:
        if key not in ALL_BUNDLES:
            raise click.BadParameter(
                f"Unknown bundle: {key!r}. "
                f"Accepted values: {', '.join(sorted(ALL_BUNDLES))}",
                param_hint="--bundle",
            )
        resolved.append(ALL_BUNDLES[key])
    return resolved


@authkit_cli.command("provision-roles")
@click.option(
    "--bundle",
    "bundle_keys",
    multiple=True,
    metavar="KEY",
    help=(
        "Bundle key to provision (repeatable). "
        "Values: dashboard_consumer, chart_author. "
        "Default: all bundles."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Force re-provisioning even if the version is already up to date.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help=(
        "Display the bundles that would be provisioned without executing any write. "
        "Combine with --force to see the full diff state."
    ),
)
@with_appcontext
def provision_roles(
    bundle_keys: tuple[str, ...],
    force: bool,
    dry_run: bool,
) -> None:
    """Idempotent provisioning of SAK roles into the Superset FAB database.

    Reads the current version from ``sak_role_version``. If the local bundle
    version matches the one in the database, execution is a no-op (clean skip).

    On update, applies the diff-set in an atomic transaction.
    A full rollback is performed if any permission fails.

    Exit codes:
        - 0: all bundles were provisioned or were already up to date.
        - 1: at least one bundle failed (details in stderr).

    Examples:

        superset authkit provision-roles

        superset authkit provision-roles --bundle dashboard_consumer --dry-run

        superset authkit provision-roles --force
    """
    from flask import current_app
    from superset_auth_kit.roles.role_reconciler import reconcile_bundle, ReconcileStatus

    bundles = _resolve_bundles(bundle_keys)
    sm = current_app.appbuilder.sm
    # FAB 5.x exposes the SQLAlchemy session as `sm.session` (not `sm.get_session`)
    session = sm.session

    if dry_run:
        click.echo("[DRY-RUN] Bundles that would be provisioned:")
        for bundle in bundles:
            click.echo(f"  - {bundle.role_name}  v{bundle.version}  "
                       f"({len(bundle.permissions)} permissions)")
        return

    errors: list[tuple[str, Exception]] = []

    for bundle in bundles:
        click.echo(
            f"  >  {bundle.role_name} v{bundle.version} "
            f"({len(bundle.permissions)} permissions)…",
            nl=False,
        )
        try:
            result = reconcile_bundle(bundle, sm, session, force=force)

            if result.status == ReconcileStatus.SKIPPED:
                click.echo("  [SKIP] already up to date.")
            elif result.status == ReconcileStatus.CREATED:
                diff = result.diff
                click.echo(
                    f"  [OK] created (+{diff.added} permissions)."  # type: ignore[union-attr]
                )
            else:  # UPDATED
                diff = result.diff
                click.echo(
                    f"  [OK] updated "
                    f"(+{diff.added} added / -{diff.removed} removed)."  # type: ignore[union-attr]
                )
        except VersionDowngradeError as exc:
            click.echo("  [ERROR: DOWNGRADE]")
            click.echo(f"    {exc}", err=True)
            click.echo(
                "    Use --force to override (use with caution).",
                err=True,
            )
            errors.append((bundle.role_name, exc))
        except RoleProvisionError as exc:
            click.echo("  [ERROR]")
            click.echo(f"    {exc}", err=True)
            errors.append((bundle.role_name, exc))
        except Exception as exc:
            click.echo("  [UNEXPECTED ERROR]")
            click.echo(f"    {type(exc).__name__}: {exc}", err=True)
            errors.append((bundle.role_name, exc))

    if errors:
        click.echo(
            f"\n[FAILED] {len(errors)}/{len(bundles)} bundle(s) failed. "
            f"See stderr for details.",
            err=True,
        )
        sys.exit(1)
    else:
        click.echo(f"\n[OK] {len(bundles)} bundle(s) provisioned successfully.")


@authkit_cli.command("check-compat")
@click.option(
    "--bundle",
    "bundle_keys",
    multiple=True,
    metavar="KEY",
    help="Bundle key to check. Default: all bundles.",
)
@with_appcontext
def check_compat(bundle_keys: tuple[str, ...]) -> None:
    """Check the compatibility of SAK bundles with the installed Superset version.

    For each ``PermSpec`` declared in ``definitions.py``, queries the FAB registry
    (``sm.find_permission_view_menu``) without creating any permission.
    Any missing permission indicates API drift between the SAK bundle and
    the installed Superset version.

    Exit codes:
        - 0: all bundles are compatible (no missing permissions).
        - 1: at least one permission is absent from the FAB registry.

    Typical usage in a CI/CD pipeline:

        superset authkit check-compat || exit 1

    This command should be run BEFORE ``provision-roles`` when upgrading the
    Superset image to detect API renames at the source.
    """
    from flask import current_app
    from superset_auth_kit.roles import capability_resolver

    bundles = _resolve_bundles(bundle_keys)
    sm = current_app.appbuilder.sm

    total_missing = 0

    for bundle in bundles:
        missing = capability_resolver.check_compat(bundle, sm)

        if not missing:
            click.echo(
                f"  [OK]  {bundle.role_name} v{bundle.version}: "
                f"all {len(bundle.permissions)} permissions present."
            )
        else:
            total_missing += len(missing)
            click.echo(
                f"  [MISSING]  {bundle.role_name} v{bundle.version}: "
                f"{len(missing)} permission(s) absent from the FAB registry:",
                err=True,
            )
            for action, view_menu in missing:
                click.echo(f"       - {action} | {view_menu}", err=True)

    if total_missing:
        click.echo(
            f"\n[FAILED] {total_missing} missing permission(s) in total. "
            f"Update definitions.py to reflect the Superset API changes.",
            err=True,
        )
        sys.exit(1)
    else:
        n_perms = sum(len(b.permissions) for b in bundles)
        click.echo(
            f"\n[OK] Compatibility verified: {n_perms} permissions across "
            f"{len(bundles)} bundle(s) — no API drift detected."
        )
