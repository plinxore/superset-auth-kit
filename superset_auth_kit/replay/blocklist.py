"""Anti-replay protection via ``jti`` (JWT ID) blocklist.

The pattern is as follows:
1. On the first presentation of a valid JWT whose ``jti`` claim is present,
   the identifier is stored with a TTL equal to the token's remaining lifetime.
2. On any subsequent presentation of the same ``jti`` before the TTL expires,
   :class:`~superset_auth_kit.exceptions.TokenReplayError` is raised.

Two backends are provided:
- :class:`InMemoryJtiStore`: thread-safe dict, for tests and single-instance deployments.
- :class:`RedisJtiStore`: Redis backend, for multi-worker / multi-instance deployments.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class JtiStore(Protocol):
    """Structural protocol for ``jti`` storage backends.

    Implementations do not need to inherit from this class;
    structural conformance is checked by ``isinstance(obj, JtiStore)``
    (``@runtime_checkable``).
    """

    def contains(self, jti: str) -> bool:
        """Return ``True`` if *jti* is present and not yet expired in the store."""
        ...

    def add(self, jti: str, ttl_seconds: int) -> None:
        """Add *jti* to the store with a TTL of *ttl_seconds* seconds."""
        ...


class InMemoryJtiStore:
    """In-process jti store backed by a thread-safe dict.

    Suitable for:
    - Unit and integration tests.
    - Single-instance Superset deployments (one worker process).

    Not suitable for multi-worker deployments (Gunicorn sync/gthread with N>1
    workers) because each process has its own dict.  Use :class:`RedisJtiStore`
    in that case.

    Expired entries are evicted lazily: cleanup happens on read.
    """

    def __init__(self) -> None:
        # dict jti → monotonic expiration timestamp
        self._store: dict[str, float] = {}
        self._lock = threading.Lock()

    def contains(self, jti: str) -> bool:
        """Return ``True`` if *jti* is known and not yet expired.

        Removes expired entries encountered during the read (lazy eviction).
        """
        with self._lock:
            exp = self._store.get(jti)
            if exp is None:
                return False
            if time.monotonic() > exp:
                del self._store[jti]
                return False
            return True

    def add(self, jti: str, ttl_seconds: int) -> None:
        """Add *jti* with a TTL of *ttl_seconds* seconds."""
        with self._lock:
            self._store[jti] = time.monotonic() + ttl_seconds


class RedisJtiStore:
    """Redis jti store for multi-worker deployments.

    Requires the ``redis`` package (project's ``[redis]`` extra).

    Args:
        client: A ``redis.Redis`` instance (or compatible, e.g. ``fakeredis.FakeRedis``).
        key_prefix: Prefix applied to each Redis key.
            Allows isolating AuthKit entries in a shared Redis instance.
    """

    def __init__(self, client: Any, key_prefix: str = "authkit:jti:") -> None:
        self._redis = client
        self._prefix = key_prefix

    def _key(self, jti: str) -> str:
        return self._prefix + jti

    def contains(self, jti: str) -> bool:
        """Return ``True`` if the Redis key corresponding to *jti* exists."""
        return bool(self._redis.exists(self._key(jti)))

    def add(self, jti: str, ttl_seconds: int) -> None:
        """Store *jti* in Redis with automatic expiration via ``SETEX``."""
        self._redis.setex(self._key(jti), ttl_seconds, "1")
