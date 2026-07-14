"""Declarative graph of business intentions → FAB permission bundles.

This file is the **single source of truth** for SAK roles. Any
modification to the graph (adding, removing, or renaming a permission)
**must** increment ``bundle.version`` to trigger idempotent reconciliation
on the next ``superset authkit provision-roles``.

Versioning rules (ADR-203):
    - Adding a permission             → bundle.version += 1
    - Removing a permission           → bundle.version += 1
    - Renaming a Superset ViewMenu    → bundle.version += 1
    - Renaming role_name              → New bundle (do not reuse)

No code outside this file should define SAK permissions.
The resolver, provisioner, and reconciler layers operate on ``CapabilityBundle``
without knowledge of the individual ``PermSpec`` values.
"""

from __future__ import annotations

from typing import NamedTuple


class PermSpec(NamedTuple):
    """(FAB action, FAB view_menu) pair — atomic unit of a permission.

    Corresponds to a row in ``ab_permission_view`` after joining with
    ``ab_permission`` (column ``name``) and ``ab_view_menu`` (column ``name``).
    """

    action: str
    view_menu: str


class CapabilityBundle(NamedTuple):
    """Versioned business intention → immutable graph of FAB permissions.

    Attributes:
        role_name:   Exact name of the FAB role created in the database (``ab_role.name``).
                     Mandatory prefix ``sak__`` for exclusive ownership.
        version:     Monotonically increasing number. Used for idempotence.
        permissions: Complete target graph (frozenset to guarantee immutability).
    """

    role_name: str
    version: int
    permissions: frozenset[PermSpec]


# ─────────────────────────────────────────────────────────────────────────────
# Bundle 1 : DashboardConsumer
# Role: sak__dashboard_consumer — Version: 1
# Profile: SaaS end-user — embedded iframe, full white-label.
# Key invariant: ZERO menu_access permissions.
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_CONSUMER = CapabilityBundle(
    role_name="sak__dashboard_consumer",
    version=1,
    permissions=frozenset({
        # ── Dashboard read access ─────────────────────────────────────────────
        PermSpec("can_read",  "Dashboard"),
        PermSpec("can_read",  "EmbeddedDashboard"),
        PermSpec("can_read",  "Chart"),
        PermSpec("can_read",  "Dataset"),
        PermSpec("can_read",  "Database"),
        PermSpec("can_read",  "Explore"),
        PermSpec("can_read",  "Tag"),
        PermSpec("can_read",  "Theme"),
        PermSpec("can_read",  "AdvancedDataType"),
        PermSpec("can_read",  "AvailableDomains"),
        PermSpec("can_read",  "RowLevelSecurity"),

        # ── Interactive state (filters, permalinks, explore form) ─────────────
        PermSpec("can_read",  "DashboardFilterStateRestApi"),
        PermSpec("can_write", "DashboardFilterStateRestApi"),
        PermSpec("can_read",  "DashboardPermalinkRestApi"),
        PermSpec("can_write", "DashboardPermalinkRestApi"),
        PermSpec("can_read",  "ExploreFormDataRestApi"),
        PermSpec("can_write", "ExploreFormDataRestApi"),
        PermSpec("can_read",  "ExplorePermalinkRestApi"),
        PermSpec("can_write", "ExplorePermalinkRestApi"),

        # ── Embedded navigation (legacy Superset endpoints) ───────────────────
        PermSpec("can_explore",                    "Superset"),
        PermSpec("can_explore_json",               "Superset"),
        PermSpec("can_dashboard",                  "Superset"),
        PermSpec("can_dashboard_permalink",        "Superset"),
        PermSpec("can_get_embedded",               "Dashboard"),
        PermSpec("can_fetch_datasource_metadata",  "Superset"),

        # ── Datasource (chart data, drill-through) ────────────────────────────
        PermSpec("can_get",                         "Datasource"),
        PermSpec("can_external_metadata",           "Datasource"),
        PermSpec("can_external_metadata_by_name",   "Datasource"),
        PermSpec("can_get_drill_info",              "Dataset"),

        # ── Utility APIs ──────────────────────────────────────────────────────
        PermSpec("can_get",       "MenuApi"),
        PermSpec("can_get",       "OpenApi"),
        PermSpec("can_query",     "Api"),
        PermSpec("can_query_form_data", "Api"),
        PermSpec("can_time_range",      "Api"),
        PermSpec("can_invalidate",      "CacheRestApi"),
        PermSpec("can_list",            "AsyncEventsRestApi"),

        # ── Dashboard interactions (drill, table view, etc.) ──────────────────
        PermSpec("can_drill",                   "Dashboard"),
        PermSpec("can_view_chart_as_table",     "Dashboard"),
        PermSpec("can_view_query",              "Dashboard"),
        PermSpec("can_put_chart_customizations","Dashboard"),
        PermSpec("can_log",                     "Superset"),
        PermSpec("can_language_pack",           "Superset"),
        PermSpec("can_file_handler",            "Superset"),
        PermSpec("can_recent_activity",         "Log"),
        PermSpec("can_list",                    "DynamicPlugin"),
        PermSpec("can_show",                    "DynamicPlugin"),
        PermSpec("can_show",                    "SwaggerView"),

        # ── System APIs (profile, security, tasks) ────────────────────────────
        PermSpec("can_read",  "CurrentUserRestApi"),
        PermSpec("can_write", "CurrentUserRestApi"),
        PermSpec("can_read",  "SecurityRestApi"),
        PermSpec("can_read",  "security"),
        PermSpec("can_read",  "user"),
        PermSpec("can_read",  "Task"),

        # ── User profile (FAB forms) ──────────────────────────────────────────
        PermSpec("can_userinfo",        "UserDBModelView"),
        PermSpec("can_this_form_get",   "ResetMyPasswordView"),
        PermSpec("can_this_form_post",  "ResetMyPasswordView"),
        PermSpec("resetmypassword",     "UserDBModelView"),

        # ── Tags (read-only) ──────────────────────────────────────────────────
        PermSpec("can_list", "Tags"),
        PermSpec("can_tags", "TagView"),
    }),
)

# ─────────────────────────────────────────────────────────────────────────────
# Bundle 2 : ChartAuthor
# Role: sak__chart_author — Version: 1
# Profile: SaaS analyst — chart and dashboard creation/editing, navigation
#          limited to business menus. No infrastructure access (DB, SQL Lab).
# Property: superset of DASHBOARD_CONSUMER + targeted write permissions.
# ─────────────────────────────────────────────────────────────────────────────

_CHART_AUTHOR_EXTRA = frozenset({
    # ── Cross-ownership database access ──────────────────────────────────────
    # Grants read-only visibility of DB connection metadata without granting
    # all_datasource_access (which would bypass Row Level Security).
    # Actual data remains isolated by RLS (account_id/org).
    PermSpec("all_database_access",   "all_database_access"),

    # ── Chart creation / editing ──────────────────────────────────────────────
    PermSpec("can_write",               "Chart"),
    PermSpec("can_slice",               "Superset"),
    PermSpec("can_export",              "Chart"),
    PermSpec("can_save",                "Datasource"),
    PermSpec("can_validate_expression", "Datasource"),
    PermSpec("can_samples",             "Datasource"),
    PermSpec("can_get_column_values",   "Datasource"),

    # ── Dashboards (write, export, share) ─────────────────────────────────────
    PermSpec("can_write",                    "Dashboard"),
    PermSpec("can_export",                   "Dashboard"),
    PermSpec("can_export_as_example",        "Dashboard"),
    PermSpec("can_cache_dashboard_screenshot","Dashboard"),
    PermSpec("can_delete_embedded",          "Dashboard"),
    PermSpec("can_share_chart",              "Superset"),
    PermSpec("can_share_dashboard",          "Superset"),

    # ── Tags and annotations ──────────────────────────────────────────────────
    PermSpec("can_write",       "Tag"),
    PermSpec("can_tag",         "Chart"),
    PermSpec("can_tag",         "Dashboard"),
    PermSpec("can_bulk_create", "Tag"),
    PermSpec("can_read",        "Annotation"),

    # ── Full SQL Lab ──────────────────────────────────────────────────────────
    # Navigation menus (SQL Lab, SQL Editor, Saved Queries, Query Search) are
    # intentionally excluded — ChartAuthor must not access SQL Lab (ADR-202 §invariant-2).
    # The execution capabilities below enable API-level SQL access without
    # exposing the SQL Lab UI.
    # Execution
    PermSpec("can_read",                  "SQLLab"),
    PermSpec("can_execute_sql_query",     "SQLLab"),
    PermSpec("can_estimate_query_cost",   "SQLLab"),
    PermSpec("can_get_results",           "SQLLab"),
    PermSpec("can_format_sql",            "SQLLab"),
    PermSpec("can_export_csv",            "SQLLab"),
    PermSpec("can_export_streaming_csv",  "SQLLab"),
    # History (filtered by user natively — no cross-tenant leak)
    PermSpec("can_read", "Query"),
    # ── SQL Lab tab state (backend persistence) ───────────────────────────────
    PermSpec("can_get",          "TabStateView"),
    PermSpec("can_post",         "TabStateView"),
    PermSpec("can_put",          "TabStateView"),
    PermSpec("can_delete",       "TabStateView"),
    PermSpec("can_activate",     "TabStateView"),
    PermSpec("can_migrate_query","TabStateView"),
    PermSpec("can_delete_query", "TabStateView"),
    # ── Table schema in SQL Lab left panel ────────────────────────────────────
    PermSpec("can_post",     "TableSchemaView"),
    PermSpec("can_delete",   "TableSchemaView"),
    PermSpec("can_expanded", "TableSchemaView"),
    # Saved queries (filtered by created_by natively)
    PermSpec("can_list",   "SavedQuery"),
    PermSpec("can_read",   "SavedQuery"),
    PermSpec("can_write",  "SavedQuery"),
    PermSpec("can_export", "SavedQuery"),

    # ── CSS, CSV, themes (read) ───────────────────────────────────────────────
    PermSpec("can_read",   "CssTemplate"),
    PermSpec("can_csv",    "Superset"),
    PermSpec("can_write",  "Theme"),
    PermSpec("can_export", "Theme"),

    # ── Navigation (8 business menus — no infrastructure menus) ──────────────
    PermSpec("menu_access", "Home"),
    PermSpec("menu_access", "Charts"),
    PermSpec("menu_access", "Dashboards"),
    PermSpec("menu_access", "Data"),
    PermSpec("menu_access", "Datasets"),
    PermSpec("menu_access", "Tags"),
    PermSpec("menu_access", "Themes"),
    PermSpec("menu_access", "Plugins"),
})

CHART_AUTHOR = CapabilityBundle(
    role_name="sak__chart_author",
    version=6,
    permissions=DASHBOARD_CONSUMER.permissions | _CHART_AUTHOR_EXTRA,
)

# ─────────────────────────────────────────────────────────────────────────────
# Bundle registry — used by the CLI and tests
# ─────────────────────────────────────────────────────────────────────────────

ALL_BUNDLES: dict[str, CapabilityBundle] = {
    "dashboard_consumer": DASHBOARD_CONSUMER,
    "chart_author":       CHART_AUTHOR,
}

# Infrastructure and SQL Lab menus forbidden for ChartAuthor (ADR-202 §invariant-2).
# Used in guard assertions.
CHART_AUTHOR_FORBIDDEN_MENUS: frozenset[str] = frozenset({
    "Databases",
    "Alerts & Report",
    "Annotation Layers",
    "CSS Templates",
    "Manage",
    "Action Log",
    "Tasks",
    # SQL Lab menus explicitly excluded (ChartAuthor must not access the SQL Lab UI)
    "SQL Lab",
    "SQL Editor",
    "Saved Queries",
    "Query Search",
})
