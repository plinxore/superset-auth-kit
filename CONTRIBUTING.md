# Contributing to superset-auth-kit

Thank you for your interest in contributing! This document describes how to set up
the development environment, run the tests, and submit a pull request.

---

## Development Setup

### Prerequisites

- Python 3.10, 3.11, or 3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or `pip`
- Git

### Clone and install

```bash
git clone https://github.com/plinxore/superset-auth-kit.git
cd superset-auth-kit

# Create a virtual environment and install all dev dependencies
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Or with `uv`:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Running the Tests

### Unit tests (no Docker required)

```bash
pytest tests/unit/ -v --tb=short -m "not integration"
```

### Unit tests with coverage

```bash
pytest tests/unit/ -v --tb=short -m "not integration" \
    --cov=superset_auth_kit \
    --cov-report=term-missing \
    --cov-fail-under=80
```

### Integration tests (requires Docker)

Integration tests spin up an ephemeral Superset container. They are opt-in and
excluded from the default run:

```bash
pytest tests/integration/ -v -m integration --timeout=300
```

The `apache/superset:latest` Docker image must be available locally or pullable.

---

## Type Checking

```bash
mypy superset_auth_kit/ --ignore-missing-imports \
    --exclude 'superset_auth_kit/cli/commands\.py'
```

The CLI module is excluded from strict mypy because it depends on Flask runtime
injection (`current_app`) which is incompatible with strict static analysis.

---

## Code Style

This project uses standard Python conventions:

- Follow [PEP 8](https://peps.python.org/pep-0008/) for code style.
- Use type annotations on all public functions and methods.
- Keep docstrings accurate and concise.
- No French text — all comments, docstrings, log messages, and error messages must
  be in English.

---

## Jinja SQL Templates — Mandatory Rule

When writing or reviewing SQL templates that use multi-tenant filtering, **always**
wrap security attributes with `cache_key_wrapper`:

```sql
-- CORRECT: tenant included in SQL AND in the cache key hash
WHERE tenant_id = '{{ cache_key_wrapper(current_tenant()) }}'

-- INCORRECT: tenant in SQL but absent from cache key (cross-tenant collision risk)
WHERE tenant_id = '{{ current_tenant() }}'
```

Without `cache_key_wrapper`, two tenants could receive each other's cached chart data.
This is a **critical isolation violation**.

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Write tests** for any new functionality. All unit tests must pass without Docker.

3. **Run the full test suite** before submitting:
   ```bash
   pytest tests/unit/ -v --tb=short -m "not integration" --cov=superset_auth_kit --cov-fail-under=80
   ```

4. **Check types**:
   ```bash
   mypy superset_auth_kit/ --ignore-missing-imports --exclude 'superset_auth_kit/cli/commands\.py'
   ```

5. **Update the CHANGELOG** under the `[Unreleased]` section with a description of
   your changes.

6. **Open a pull request** against `main`. Include in the description:
   - What the change does and why
   - Whether it is a breaking change (API, CLI, role names)
   - Reference to any related issue

### Breaking changes

Breaking changes require a MAJOR version bump per [SemVer](https://semver.org/):

| Breaking change | Example |
|-----------------|---------|
| Rename or remove a bundle `role_name` | `sak__dashboard_consumer` → `sak__dc` |
| Remove or rename a public Python API | Exception classes, `build_manager` signature |
| Change supported Superset/FAB version | Drop Superset 6.1 support |

Non-breaking changes (new bundles, bug fixes, new CLI options) use MINOR or PATCH.

---

## Adding a New Permission Bundle

1. Add a new `CapabilityBundle` in `superset_auth_kit/roles/definitions.py`.
2. Set `version = 1` for the initial definition.
3. Add an entry in `BUNDLES` dict with a stable snake_case key.
4. Write unit tests in `tests/unit/test_roles.py`:
   - Verify the permission graph is correct.
   - Verify tightness invariants (e.g., no `menu_access` for embed-only bundles).
5. Run `superset authkit check-compat` to verify all permissions exist in the
   target Superset version.
6. Update the CHANGELOG.

When modifying an existing bundle, always increment `bundle.version`. See
`docs/adr/ADR-002-role-management.md` for the full versioning protocol.

---

## Security Issues

Please do **not** open a public GitHub issue for security vulnerabilities.
Report security issues to the maintainers by email instead.

---

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
