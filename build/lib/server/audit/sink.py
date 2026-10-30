"""Write-only, hash-chained JSONL audit sink (doc §18.6).

Each line's `prev_hash` links to the previous line's `hash`, per day. A
nightly (or on-demand) verification pass can walk the chain and detect any
gap or edit. Production hardening would add an external rolling-digest
anchor and ship this off-box continuously; this module is the local part
that would feed such a pipeline.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

# Deliberately NOT common.canonical here: that module exists for proposal
# hashing, where floats are banned to keep the scheme strict. Audit records
# routinely carry float timestamps and only need a deterministic,
# tamper-evident hash -- not JCS-grade canonicalization -- so this uses a
# plain sorted-key json.dumps instead.
GENESIS_HASH = "0" * 64


class AuditSink:
    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._last_hash: str | None = None

    def _path_for_today(self) -> Path:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        return self._log_dir / f"audit-{day}.jsonl"

    def _load_last_hash(self, path: Path) -> str:
        if not path.exists():
            return GENESIS_HASH
        last_line = None
        with path.open("rb") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return GENESIS_HASH
        return json.loads(last_line)["hash"]

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        path = self._path_for_today()
        if self._last_hash is None:
            self._last_hash = self._load_last_hash(path)

        entry = dict(record)
        entry["prev_hash"] = self._last_hash
        entry_hash = _hash_entry(entry)
        entry["hash"] = entry_hash

        with path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")

        self._last_hash = entry_hash
        return entry

    def verify_chain(self, path: Path) -> bool:
        prev = GENESIS_HASH
        if not path.exists():
            return True
        with path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                claimed_hash = entry.pop("hash")
                if entry.get("prev_hash") != prev:
                    return False
                if _hash_entry(entry) != claimed_hash:
                    return False
                prev = claimed_hash
        return True


def _hash_entry(entry_without_hash: dict[str, Any]) -> str:
    encoded = json.dumps(entry_without_hash, sort_keys=True, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
