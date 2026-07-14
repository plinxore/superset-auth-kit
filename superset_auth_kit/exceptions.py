"""Exception hierarchy for superset-auth-kit.

All business exceptions inherit from :class:`AuthKitError` so that callers
using ``except AuthKitError`` can catch any error from the package without
importing each subclass individually.
"""

from __future__ import annotations


class AuthKitError(Exception):
    """Base class for all superset-auth-kit errors."""


class TokenExpiredError(AuthKitError):
    """The token has exceeded its expiration date (``exp`` claim)."""


class TokenInvalidError(AuthKitError):
    """The token is malformed, the signature is invalid, or claims are unacceptable."""


class TokenReplayError(TokenInvalidError):
    """The ``jti`` claim of the token has already been consumed (replay protection).

    Subclass of :class:`TokenInvalidError` to propagate via ``except TokenInvalidError``,
    but must be caught *before* it to return a distinct 403 response.
    """


class RoleEscalationError(AuthKitError):
    """Attempt to assign a privileged role (e.g. Admin) via SSO.

    Raised both during construction of :class:`~superset_auth_kit.sync.role_mapper.RoleMapper`
    (invalid configuration) and during dynamic role resolution.
    """


class RoleNotAllowedError(AuthKitError):
    """The resolved role is not present in the ``allowed_roles`` whitelist."""


class TenantResolutionError(AuthKitError):
    """``tenant_id`` is malformed or does not match the validation pattern.

    Raised by :meth:`~superset_auth_kit.tenant.context.TenantContext.set_tenant`
    when the value does not match the pattern ``^[a-zA-Z0-9_-]{1,128}$``.
    """


class TenantContextMissingError(TenantResolutionError):
    """No ``tenant_id`` is defined in the current execution context.

    Raised by :meth:`~superset_auth_kit.tenant.context.TenantContext.get_tenant`
    when the ContextVar is ``None`` (request not authenticated via SSO, or
    the ``before_request`` hook was not triggered).

    Subclass of :class:`TenantResolutionError` to allow a global ``except
    TenantResolutionError`` while also permitting precise interception
    via ``except TenantContextMissingError``.

    **Fail Closed policy**: the exception immediately halts execution of
    the Jinja SQL template — no query executes without a tenant filter.
    """


class UserSyncError(AuthKitError):
    """Creation or update of the FAB user failed."""


class InvalidRedirectError(AuthKitError):
    """The ``redirect_to`` value is not a safe relative path."""


# ── Role subsystem (ADR-002) ──────────────────────────────────────────────────


class RoleProvisionError(AuthKitError):
    """Failed to provision a SAK role in the FAB database.

    Raised by :mod:`superset_auth_kit.roles.role_reconciler` when resolution
    or application of the diff-set fails. The transaction is rolled back before
    the exception is raised — the database is always left in a consistent state.
    """


class VersionDowngradeError(RoleProvisionError):
    """The local bundle version is lower than the version stored in the database.

    Example: bundle.version=1 while sak_role_version records version=2.
    Protects against accidental deployment of an older image.
    Use ``--force`` to override (with explicit confirmation).
    """


class PermissionNotFoundError(RoleProvisionError):
    """A permission declared in a bundle is absent from the FAB registry.

    Raised by ``superset authkit check-compat`` when
    ``sm.find_permission_view_menu(action, view_menu)`` returns ``None``
    for a ``PermSpec`` declared in ``definitions.py``.
    Indicates an API drift between the installed Superset version and the
    SAK bundles.
    """
