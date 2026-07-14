"""SHA-256 fingerprint generation for an Identity to detect changes.

The fingerprint covers only the fields that result in a FAB database write
(email, first name, last name, roles, tenant).  Timestamps and metadata are
intentionally excluded: their variation must not trigger a superfluous ``update_user``.

Serialization uses ``json.dumps`` with ``sort_keys=True`` and ASCII encoding
to guarantee a **deterministic result across Python restarts** —
unlike the builtin ``hash()`` whose seed (PYTHONHASHSEED) changes with each process.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from superset_auth_kit.providers._base import Identity


class IdentityFingerprint:
    """Computation and storage of the SHA-256 fingerprint of an :class:`~superset_auth_kit.providers._base.Identity`."""

    @staticmethod
    def compute(identity: Identity) -> str:
        """Return the hexadecimal SHA-256 digest of the FAB-persisted fields.

        Args:
            identity: The identity whose fingerprint should be computed.

        Returns:
            64-character hexadecimal string (SHA-256).
        """
        payload: dict[str, Any] = {
            "email": identity.email,
            "first_name": identity.first_name,
            "last_name": identity.last_name,
            "roles": sorted(identity.roles),   # sorted to guarantee determinism
            "tenant_id": identity.tenant_id,
        }
        serialised: str = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    @staticmethod
    def from_user_extra_json(extra_json: dict[str, Any] | None) -> str | None:
        """Extract the stored fingerprint from ``User.extra_json``.

        Args:
            extra_json: The ``extra_json`` dictionary from the FAB User object,
                or ``None`` if the field is empty.

        Returns:
            The previous fingerprint as a hex string, or ``None``
            if no fingerprint has been stored yet (first login, or user
            created outside superset-auth-kit).
        """
        if not extra_json or not isinstance(extra_json, dict):
            return None
        value = extra_json.get("authkit_fp")
        return str(value) if isinstance(value, str) else None
