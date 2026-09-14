"""Per-request devd token minting (doc §9.3). The control plane holds the
PRIVATE half of this keypair; devd holds only the public half (devd/auth.py).
A token authorizes exactly one operation, for about two minutes.
"""

from __future__ import annotations

import time
from pathlib import Path

import jwt


class TokenMinter:
    def __init__(self, private_key_pem: str):
        self._private_key = private_key_pem

    @classmethod
    def from_file(cls, path: Path) -> "TokenMinter":
        return cls(path.read_text())

    def mint(
        self,
        *,
        sub: str,
        approval_id: str,
        operation_id: str,
        manifest_version: int,
        audience: str,
        ttl_seconds: int = 120,
    ) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "approval_id": approval_id,
            "operation_id": operation_id,
            "manifest_ver": manifest_version,
            "aud": audience,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        return jwt.encode(payload, self._private_key, algorithm="EdDSA")
