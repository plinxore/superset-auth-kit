"""Global pytest configuration for superset-auth-kit."""

from __future__ import annotations


def pytest_configure(config: object) -> None:
    """Register custom markers."""
    import pytest  # noqa: PLC0415 — intentional local import

    assert isinstance(config, pytest.Config)
    config.addinivalue_line(
        "markers",
        "integration: integration test requiring Docker (excluded by default with -m 'not integration')",
    )
    config.addinivalue_line(
        "markers",
        "slow: slow test (> 10s)",
    )
