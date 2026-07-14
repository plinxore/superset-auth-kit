"""Pytest fixtures for integration tests — ephemeral Superset container.

Requires:
- Docker available (``docker.from_env()``).
- Image ``apache/superset:latest`` available locally (or pullable).
- The project directory (superset-auth-kit) accessible for reading.

Usage:
    pytest -v -m integration tests/integration/
    pytest -v -m "not integration" tests/   # exclude integration tests
"""

from __future__ import annotations

import pathlib
import time
from typing import Generator

import pytest

# Project root of superset-auth-kit (two levels above tests/integration/)
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent.parent.resolve()
_CONFIG_PATH_IN_CONTAINER = "/authkit/tests/integration/superset_config_for_tests.py"

SUPERSET_IMAGE = "apache/superset:latest"
SUPERSET_HOST_PORT = 8099  # avoids conflict with superset-embed (8088)
_HEALTH_TIMEOUT_SECONDS = 240

# Startup command:
# 1. Copy source into /tmp (avoids permission conflicts on .egg-info
#    owned by the host user, not writable by the container user).
# 2. Remove any existing build artifacts.
# 3. Install the package, initialize Superset, and start the server.
_STARTUP_CMD = (
    "cp -r /authkit /tmp/authkit_src && "
    "rm -rf /tmp/authkit_src/*.egg-info /tmp/authkit_src/.venv && "
    "uv pip install --python /app/.venv/bin/python --no-cache /tmp/authkit_src[api] && "
    "superset db upgrade && "
    "superset fab create-admin "
    "  --username admin --firstname Admin --lastname Superset "
    "  --email admin@localhost --password admin && "
    "superset init && "
    "superset run -p 8088 --host 0.0.0.0 --with-threads"
)


def _wait_for_health(base_url: str, timeout: int = _HEALTH_TIMEOUT_SECONDS) -> bool:
    """Poll ``GET /health`` until a 200 is received or the timeout expires."""
    import requests  # late import — requests is not a hard dependency of the package

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{base_url}/health", timeout=5)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


@pytest.fixture(scope="session")
def superset_container() -> Generator[str, None, None]:
    """Launch an ephemeral Superset container and yield its base URL.

    The container is cleanly destroyed at the end of the test session,
    even on failure.

    Yields:
        Base URL of the ephemeral Superset instance (e.g. ``http://localhost:8099``).

    Skip:
        If Docker is not available in the environment.
    """
    try:
        import docker  # type: ignore[import-untyped]
    except ImportError:
        pytest.skip("Package 'docker' not installed — pip install docker")

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        pytest.skip(f"Docker not accessible: {exc}")

    container = None
    base_url = f"http://localhost:{SUPERSET_HOST_PORT}"

    try:
        container = client.containers.run(
            SUPERSET_IMAGE,
            command=["bash", "-c", _STARTUP_CMD],
            detach=True,
            # user="root": required to write into /app/.venv (root-owned venv).
            # Acceptable for ephemeral integration tests.
            user="root",
            environment={
                "SUPERSET_CONFIG_PATH": _CONFIG_PATH_IN_CONTAINER,
            },
            volumes={
                str(_PROJECT_ROOT): {"bind": "/authkit", "mode": "ro"},
            },
            ports={"8088/tcp": SUPERSET_HOST_PORT},
            name="authkit-integration-test",
            auto_remove=False,
        )

        if not _wait_for_health(base_url):
            logs = container.logs(tail=100).decode(errors="replace")
            pytest.fail(
                f"Superset container did not start within {_HEALTH_TIMEOUT_SECONDS}s.\n"
                f"Last logs:\n{logs}"
            )

        yield base_url

    finally:
        if container is not None:
            try:
                container.stop(timeout=10)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass
