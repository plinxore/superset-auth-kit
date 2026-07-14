"""ADR-002 Phase 4: Tests for role bundles, reconciliation, and the CLI.

Four test classes:

1. ``TestDefinitionsInvariants``
   Static properties of bundles declared in definitions.py (zero mocks,
   frozenset operations only). Verifies all ADR-202 invariants.

2. ``TestCapabilityResolver``
   PermSpec → PermissionView resolution via a mocked SM (find + add).

3. ``TestRoleReconciler``
   Full algorithm: version check, diff-set, commit/rollback.
   Covers: skip, create, update, downgrade, force, rollback.

4. ``TestReconcilerSovereignty``
   Exclusive sovereignty: refusal to touch non-SAK roles.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from superset_auth_kit.exceptions import (
    RoleProvisionError,
    VersionDowngradeError,
)
from superset_auth_kit.roles.definitions import (
    ALL_BUNDLES,
    CHART_AUTHOR,
    CHART_AUTHOR_FORBIDDEN_MENUS,
    DASHBOARD_CONSUMER,
    PermSpec,
)
from superset_auth_kit.roles import capability_resolver, role_provisioner
from superset_auth_kit.roles.role_reconciler import (
    ReconcileStatus,
    reconcile_bundle,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — FAB mocks
# ─────────────────────────────────────────────────────────────────────────────


class _MockPV:
    """FAB PermissionView stub."""

    def __init__(self, action: str, view_menu: str) -> None:
        self.permission = MagicMock(name=action)
        self.permission.name = action
        self.view_menu = MagicMock(name=view_menu)
        self.view_menu.name = view_menu

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _MockPV):
            return NotImplemented
        return (self.permission.name, self.view_menu.name) == (
            other.permission.name,
            other.view_menu.name,
        )

    def __hash__(self) -> int:
        return hash((self.permission.name, self.view_menu.name))

    def __repr__(self) -> str:
        return f"PV({self.permission.name}|{self.view_menu.name})"


class _MockRole:
    """FAB ab_role stub."""

    def __init__(self, name: str, role_id: int = 1) -> None:
        self.id = role_id
        self.name = name


class _FakeSM:
    """Minimal FAB SecurityManager stub for unit tests.

    Maintains its own in-memory registry of roles and permissions.
    """

    def __init__(self) -> None:
        self._roles: dict[str, _MockRole] = {}
        self._pv_registry: dict[tuple[str, str], _MockPV] = {}
        self._role_pvs: dict[str, set[_MockPV]] = {}  # role_name → pvs
        self._next_role_id = 1

    # ── FAB role API ──────────────────────────────────────────────────────────

    def find_role(self, name: str) -> _MockRole | None:
        return self._roles.get(name)

    def add_role(self, name: str) -> _MockRole:
        role = _MockRole(name, self._next_role_id)
        self._next_role_id += 1
        self._roles[name] = role
        self._role_pvs[name] = set()
        return role

    # ── FAB permission API ────────────────────────────────────────────────────

    def find_permission_view_menu(self, action: str, view_menu: str) -> _MockPV | None:
        return self._pv_registry.get((action, view_menu))

    def add_permission_view_menu(self, action: str, view_menu: str) -> _MockPV:
        pv = _MockPV(action, view_menu)
        self._pv_registry[(action, view_menu)] = pv
        return pv

    def add_permission_role(self, role: _MockRole, pv: _MockPV) -> None:
        self._role_pvs.setdefault(role.name, set()).add(pv)

    def del_permission_role(self, role: _MockRole, pv: _MockPV) -> None:
        self._role_pvs.get(role.name, set()).discard(pv)

    def get_db_role_permissions(self, role_id: int) -> list[_MockPV]:
        for name, role in self._roles.items():
            if role.id == role_id:
                return list(self._role_pvs.get(name, set()))
        return []

    # ── Test helper ───────────────────────────────────────────────────────────

    def seed_pv_registry(self, *specs: PermSpec) -> None:
        """Pre-load PermissionView objects into the registry (simulates superset init)."""
        for ps in specs:
            self.add_permission_view_menu(ps.action, ps.view_menu)


class _MockSession:
    """SQLAlchemy session stub for unit tests."""

    def __init__(self, stored_versions: dict[str, int] | None = None) -> None:
        self._stored: dict[str, int] = stored_versions or {}
        self.committed = False
        self.rolled_back = False
        self._ddl_executed = False

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        stmt_text = str(stmt)

        if "CREATE TABLE" in stmt_text:
            self._ddl_executed = True
            return MagicMock()

        if "SELECT bundle_version" in stmt_text:
            role_name = (params or {}).get("role_name", "")
            version = self._stored.get(role_name)
            mock_result = MagicMock()
            mock_result.fetchone.return_value = (version,) if version is not None else None
            return mock_result

        if "INSERT INTO sak_role_version" in stmt_text:
            role_name = (params or {}).get("role_name", "")
            version = (params or {}).get("bundle_version", 0)
            self._stored[role_name] = version
            return MagicMock()

        return MagicMock()

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


# ─────────────────────────────────────────────────────────────────────────────
# 1. Definition invariants (zero mocks)
# ─────────────────────────────────────────────────────────────────────────────


class TestDefinitionsInvariants:
    """Static properties of bundles — verified directly on the frozensets."""

    def test_all_bundles_registered_in_all_bundles_dict(self) -> None:
        """All declared bundles are accessible via ALL_BUNDLES."""
        assert "dashboard_consumer" in ALL_BUNDLES
        assert "chart_author" in ALL_BUNDLES
        assert ALL_BUNDLES["dashboard_consumer"] is DASHBOARD_CONSUMER
        assert ALL_BUNDLES["chart_author"] is CHART_AUTHOR

    def test_bundle_versions_are_positive_integers(self) -> None:
        for key, bundle in ALL_BUNDLES.items():
            assert bundle.version >= 1, (
                f"{key}.version must be >= 1 (current value: {bundle.version})"
            )

    def test_bundle_role_names_have_sak_prefix(self) -> None:
        for key, bundle in ALL_BUNDLES.items():
            assert bundle.role_name.startswith("sak__"), (
                f"{key}.role_name={bundle.role_name!r} must start with 'sak__'"
            )

    def test_bundle_permissions_are_nonempty_frozensets(self) -> None:
        for key, bundle in ALL_BUNDLES.items():
            assert isinstance(bundle.permissions, frozenset), (
                f"{key}.permissions must be a frozenset"
            )
            assert len(bundle.permissions) > 0, (
                f"{key}.permissions must not be empty"
            )

    # ── DashboardConsumer invariants ──────────────────────────────────────────

    def test_dashboard_consumer_has_zero_menu_access(self) -> None:
        """Fundamental invariant ADR-202 §1: DashboardConsumer — zero menu_access."""
        offenders = [
            ps for ps in DASHBOARD_CONSUMER.permissions
            if ps.action == "menu_access"
        ]
        assert offenders == [], (
            f"DashboardConsumer MUST HAVE NO menu_access permissions. "
            f"Offenders: {offenders}"
        )

    def test_dashboard_consumer_excludes_write_on_chart(self) -> None:
        assert PermSpec("can_write", "Chart") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_excludes_write_on_dashboard(self) -> None:
        assert PermSpec("can_write", "Dashboard") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_excludes_write_on_tag(self) -> None:
        assert PermSpec("can_write", "Tag") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_excludes_csv_export(self) -> None:
        assert PermSpec("can_csv", "Superset") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_excludes_export_chart(self) -> None:
        assert PermSpec("can_export", "Chart") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_excludes_sql_lab(self) -> None:
        assert PermSpec("can_export_streaming_csv", "SQLLab") not in DASHBOARD_CONSUMER.permissions

    def test_dashboard_consumer_has_required_read_permissions(self) -> None:
        required = [
            PermSpec("can_read", "Dashboard"),
            PermSpec("can_read", "Chart"),
            PermSpec("can_read", "Dataset"),
            PermSpec("can_explore_json", "Superset"),
            PermSpec("can_read", "CurrentUserRestApi"),
            PermSpec("can_read", "SecurityRestApi"),
        ]
        for ps in required:
            assert ps in DASHBOARD_CONSUMER.permissions, (
                f"DashboardConsumer must contain {ps}"
            )

    # ── ChartAuthor invariants ────────────────────────────────────────────────

    def test_chart_author_is_superset_of_dashboard_consumer(self) -> None:
        """ChartAuthor contains all DashboardConsumer permissions."""
        assert DASHBOARD_CONSUMER.permissions.issubset(CHART_AUTHOR.permissions), (
            "All DashboardConsumer permissions must be present in ChartAuthor"
        )

    def test_chart_author_has_write_on_chart(self) -> None:
        assert PermSpec("can_write", "Chart") in CHART_AUTHOR.permissions

    def test_chart_author_has_write_on_dashboard(self) -> None:
        assert PermSpec("can_write", "Dashboard") in CHART_AUTHOR.permissions

    def test_chart_author_has_exactly_8_menu_access_perms(self) -> None:
        """ChartAuthor exposes exactly 8 business menus (ADR-202 §2)."""
        menu_perms = [
            ps for ps in CHART_AUTHOR.permissions if ps.action == "menu_access"
        ]
        assert len(menu_perms) == 8, (
            f"ChartAuthor must have 8 menu_access permissions, found: "
            f"{len(menu_perms)} — {[ps.view_menu for ps in menu_perms]}"
        )

    def test_chart_author_menu_access_correct_set(self) -> None:
        expected_menus = {"Home", "Charts", "Dashboards", "Data", "Datasets", "Tags", "Themes", "Plugins"}
        actual_menus = {
            ps.view_menu
            for ps in CHART_AUTHOR.permissions
            if ps.action == "menu_access"
        }
        assert actual_menus == expected_menus

    def test_chart_author_excludes_forbidden_infrastructure_menus(self) -> None:
        """Invariant ADR-202 §2: no infrastructure menus in ChartAuthor."""
        offenders = [
            ps for ps in CHART_AUTHOR.permissions
            if ps.action == "menu_access" and ps.view_menu in CHART_AUTHOR_FORBIDDEN_MENUS
        ]
        assert offenders == [], (
            f"ChartAuthor exposes forbidden infrastructure menus: {offenders}"
        )

    def test_chart_author_excludes_all_datasource_access(self) -> None:
        assert PermSpec("all_datasource_access", "all_datasource_access") not in CHART_AUTHOR.permissions
        # Verify under all potential forms
        for ps in CHART_AUTHOR.permissions:
            assert "all_datasource_access" not in ps.action.lower() or ps.action == "all_datasource_access" and False, (
                f"ChartAuthor must not have all_datasource_access: {ps}"
            )

    def test_chart_author_excludes_dataset_write(self) -> None:
        assert PermSpec("can_write", "Dataset") not in CHART_AUTHOR.permissions

    def test_chart_author_excludes_sql_lab_menu(self) -> None:
        assert PermSpec("menu_access", "SQL Lab") not in CHART_AUTHOR.permissions

    def test_chart_author_has_more_perms_than_dashboard_consumer(self) -> None:
        extra = CHART_AUTHOR.permissions - DASHBOARD_CONSUMER.permissions
        assert len(extra) > 0, "ChartAuthor must have additional permissions"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Resolver (PermSpec → PermissionView materialization)
# ─────────────────────────────────────────────────────────────────────────────


class TestCapabilityResolver:
    """Tests for capability_resolver.resolve and check_compat."""

    def test_resolve_finds_existing_permissions(self) -> None:
        """Permissions already in FAB registry → find, no creation."""
        sm = _FakeSM()
        sm.seed_pv_registry(*DASHBOARD_CONSUMER.permissions)

        pvs = capability_resolver.resolve(DASHBOARD_CONSUMER, sm)

        assert len(pvs) == len(DASHBOARD_CONSUMER.permissions)

    def test_resolve_creates_missing_permissions(self) -> None:
        """Permissions absent from registry → add_permission_view_menu created."""
        sm = _FakeSM()
        # Empty registry — all permissions must be created
        pvs = capability_resolver.resolve(DASHBOARD_CONSUMER, sm)

        assert len(pvs) == len(DASHBOARD_CONSUMER.permissions)
        # Verify that the registry was populated
        for ps in DASHBOARD_CONSUMER.permissions:
            assert sm.find_permission_view_menu(ps.action, ps.view_menu) is not None

    def test_resolve_returns_frozenset(self) -> None:
        sm = _FakeSM()
        result = capability_resolver.resolve(DASHBOARD_CONSUMER, sm)
        assert isinstance(result, frozenset)

    def test_check_compat_all_present_returns_empty(self) -> None:
        """check_compat → empty list if all permissions are in the registry."""
        sm = _FakeSM()
        sm.seed_pv_registry(*DASHBOARD_CONSUMER.permissions)

        missing = capability_resolver.check_compat(DASHBOARD_CONSUMER, sm)
        assert missing == []

    def test_check_compat_detects_missing_permissions(self) -> None:
        """check_compat → returns absent PermSpec objects without creating them."""
        sm = _FakeSM()
        # Do not pre-load the registry → everything is missing

        missing = capability_resolver.check_compat(DASHBOARD_CONSUMER, sm)

        assert len(missing) == len(DASHBOARD_CONSUMER.permissions)
        # Verify that check_compat did NOT create any permissions
        for ps in DASHBOARD_CONSUMER.permissions:
            assert sm.find_permission_view_menu(ps.action, ps.view_menu) is None, (
                "check_compat must not create permissions (read-only)"
            )

    def test_check_compat_returns_sorted_list(self) -> None:
        sm = _FakeSM()
        missing = capability_resolver.check_compat(DASHBOARD_CONSUMER, sm)
        # Must be sorted (action, view_menu)
        assert missing == sorted(missing)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Reconciler — full algorithm
# ─────────────────────────────────────────────────────────────────────────────


class TestRoleReconciler:
    """Tests for role_reconciler.reconcile_bundle."""

    # ── Nominal case: creation ────────────────────────────────────────────────

    def test_reconcile_new_bundle_creates_role(self) -> None:
        """First provisioning of a bundle → role created in the database."""
        sm = _FakeSM()
        session = _MockSession()

        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert result.status == ReconcileStatus.CREATED
        assert result.role_name == "sak__dashboard_consumer"
        assert result.version == 1
        assert result.diff is not None
        assert result.diff.added == len(DASHBOARD_CONSUMER.permissions)
        assert result.diff.removed == 0
        assert session.committed
        assert not session.rolled_back

    def test_reconcile_creates_role_in_fab(self) -> None:
        """The FAB role is actually created in the SM."""
        sm = _FakeSM()
        session = _MockSession()

        reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        role = sm.find_role("sak__dashboard_consumer")
        assert role is not None
        assert role.name == "sak__dashboard_consumer"

    def test_reconcile_stores_version_in_session(self) -> None:
        """The version is written to sak_role_version after provisioning."""
        sm = _FakeSM()
        session = _MockSession()

        reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        stored = role_provisioner.get_stored_version(session, "sak__dashboard_consumer")
        assert stored == 1

    # ── Nominal case: skip (idempotence) ─────────────────────────────────────

    def test_reconcile_same_version_skips(self) -> None:
        """Same version in database → skip without write (O(1) idempotence)."""
        sm = _FakeSM()
        session = _MockSession(
            stored_versions={"sak__dashboard_consumer": 1}
        )

        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert result.status == ReconcileStatus.SKIPPED
        assert result.diff is None
        assert not session.committed

    # ── Nominal case: update ──────────────────────────────────────────────────

    def test_reconcile_older_stored_version_updates(self) -> None:
        """Stored version < bundle version → update (upgrade)."""
        sm = _FakeSM()
        # Simulate an existing role with some permissions
        sm.add_role("sak__dashboard_consumer")
        sm.seed_pv_registry(
            PermSpec("can_read", "Dashboard"),
            PermSpec("can_read", "Chart"),
        )
        pv1 = sm.find_permission_view_menu("can_read", "Dashboard")
        pv2 = sm.find_permission_view_menu("can_read", "Chart")
        role = sm.find_role("sak__dashboard_consumer")
        sm.add_permission_role(role, pv1)  # type: ignore[arg-type]
        sm.add_permission_role(role, pv2)  # type: ignore[arg-type]

        # Version 0 in database, bundle is v1 → upgrade
        session = _MockSession(stored_versions={"sak__dashboard_consumer": 0})

        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert result.status == ReconcileStatus.UPDATED
        assert result.diff is not None
        # The 2 already-present permissions are not re-added
        assert result.diff.added == len(DASHBOARD_CONSUMER.permissions) - 2
        assert result.diff.removed == 0
        assert session.committed

    def test_reconcile_removes_extra_permissions(self) -> None:
        """Permissions in database absent from the target bundle → removed."""
        sm = _FakeSM()
        sm.add_role("sak__dashboard_consumer")
        # Add an out-of-bundle permission
        sm.seed_pv_registry(PermSpec("can_write", "Dataset"))
        pv_extra = sm.find_permission_view_menu("can_write", "Dataset")
        role = sm.find_role("sak__dashboard_consumer")
        sm.add_permission_role(role, pv_extra)  # type: ignore[arg-type]

        session = _MockSession(stored_versions={"sak__dashboard_consumer": 0})

        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert result.diff is not None
        assert result.diff.removed == 1, (
            "The out-of-bundle permission must be removed"
        )

    # ── Error case: downgrade ─────────────────────────────────────────────────

    def test_reconcile_higher_stored_version_raises_downgrade_error(self) -> None:
        """Stored version > bundle version → VersionDowngradeError."""
        sm = _FakeSM()
        session = _MockSession(
            stored_versions={"sak__dashboard_consumer": 99}
        )

        with pytest.raises(VersionDowngradeError) as exc_info:
            reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert "Downgrade refused" in str(exc_info.value)
        assert "99" in str(exc_info.value)

    def test_reconcile_force_bypasses_version_check(self) -> None:
        """--force bypasses version checking."""
        sm = _FakeSM()
        session = _MockSession(
            stored_versions={"sak__dashboard_consumer": 1}
        )

        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session, force=True)

        assert result.status in (ReconcileStatus.CREATED, ReconcileStatus.UPDATED)
        assert session.committed

    def test_reconcile_force_also_bypasses_downgrade(self) -> None:
        """--force allows forcing even when the database has a higher version."""
        sm = _FakeSM()
        session = _MockSession(
            stored_versions={"sak__dashboard_consumer": 99}
        )

        # Must not raise VersionDowngradeError
        result = reconcile_bundle(DASHBOARD_CONSUMER, sm, session, force=True)
        assert result.status in (ReconcileStatus.CREATED, ReconcileStatus.UPDATED)

    # ── Error case: transactional rollback ────────────────────────────────────

    def test_reconcile_rolls_back_on_add_permission_failure(self) -> None:
        """Error on add_permission_role → full rollback."""
        sm = _FakeSM()
        session = _MockSession()

        # Make add_permission_role fail
        original_add = sm.add_permission_role
        call_count = [0]

        def _failing_add(role: Any, pv: Any) -> None:
            call_count[0] += 1
            if call_count[0] > 5:
                raise RuntimeError("Simulated DB constraint violation")
            original_add(role, pv)

        sm.add_permission_role = _failing_add  # type: ignore[method-assign]

        with pytest.raises(RoleProvisionError) as exc_info:
            reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        assert session.rolled_back, "A rollback must have been performed"
        assert not session.committed, "No commit must have occurred"
        assert "Provisioning failed" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Exclusive sovereignty
# ─────────────────────────────────────────────────────────────────────────────


class TestReconcilerSovereignty:
    """SAK refuses to touch roles without the sak__ prefix."""

    @pytest.mark.parametrize("native_role", [
        "Admin", "Gamma", "Alpha", "Public", "sql_lab",
    ])
    def test_reconcile_refuses_native_role_names(self, native_role: str) -> None:
        """reconcile_bundle raises ValueError for names without the sak__ prefix."""
        from superset_auth_kit.roles.definitions import CapabilityBundle

        fake_bundle = CapabilityBundle(
            role_name=native_role,
            version=1,
            permissions=frozenset({PermSpec("can_read", "Dashboard")}),
        )
        sm = _FakeSM()
        session = _MockSession()

        with pytest.raises(ValueError, match="sak__"):
            reconcile_bundle(fake_bundle, sm, session)

    def test_reconcile_accepts_sak_prefixed_roles(self) -> None:
        """reconcile_bundle accepts names with the sak__ prefix."""
        from superset_auth_kit.roles.definitions import CapabilityBundle

        bundle = CapabilityBundle(
            role_name="sak__custom_test_role",
            version=1,
            permissions=frozenset({PermSpec("can_read", "Dashboard")}),
        )
        sm = _FakeSM()
        session = _MockSession()

        result = reconcile_bundle(bundle, sm, session)
        assert result.status == ReconcileStatus.CREATED

    def test_native_roles_unchanged_during_provisioning(self) -> None:
        """Native roles present in the SM are not modified."""
        sm = _FakeSM()
        # Simulate pre-existing native roles
        for native in ("Admin", "Gamma", "Alpha"):
            sm._roles[native] = _MockRole(native, role_id=100)

        session = _MockSession()
        reconcile_bundle(DASHBOARD_CONSUMER, sm, session)

        # Native roles remain intact
        for native in ("Admin", "Gamma", "Alpha"):
            assert sm._roles[native].id == 100, (
                f"Native role {native} was modified by SAK"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 5. role_provisioner (direct SQL layer)
# ─────────────────────────────────────────────────────────────────────────────


class TestRoleProvisioner:
    """Unit tests for the sak_role_version SQL layer."""

    def test_ensure_version_table_executes_ddl(self) -> None:
        session = _MockSession()
        role_provisioner.ensure_version_table(session)
        assert session._ddl_executed

    def test_get_stored_version_returns_none_on_first_run(self) -> None:
        session = _MockSession()
        version = role_provisioner.get_stored_version(session, "sak__test")
        assert version is None

    def test_get_stored_version_returns_correct_version(self) -> None:
        session = _MockSession(stored_versions={"sak__test": 42})
        version = role_provisioner.get_stored_version(session, "sak__test")
        assert version == 42

    def test_upsert_version_writes_version(self) -> None:
        session = _MockSession()
        role_provisioner.upsert_version(session, "sak__test", 7)
        assert session._stored["sak__test"] == 7

    def test_apply_diff_adds_missing_permissions(self) -> None:
        sm = _FakeSM()
        role = sm.add_role("sak__test")
        target_pvs = frozenset({
            sm.add_permission_view_menu("can_read", "Dashboard"),
            sm.add_permission_view_menu("can_read", "Chart"),
        })

        diff = role_provisioner.apply_diff(role, target_pvs, sm)

        assert diff.added == 2
        assert diff.removed == 0

    def test_apply_diff_removes_extra_permissions(self) -> None:
        sm = _FakeSM()
        role = sm.add_role("sak__test")
        pv_extra = sm.add_permission_view_menu("can_write", "Dataset")
        sm.add_permission_role(role, pv_extra)

        diff = role_provisioner.apply_diff(role, frozenset(), sm)

        assert diff.removed == 1
        assert diff.added == 0

    def test_apply_diff_no_op_when_already_in_sync(self) -> None:
        sm = _FakeSM()
        role = sm.add_role("sak__test")
        pv = sm.add_permission_view_menu("can_read", "Dashboard")
        sm.add_permission_role(role, pv)

        diff = role_provisioner.apply_diff(role, frozenset({pv}), sm)

        assert diff.added == 0
        assert diff.removed == 0
