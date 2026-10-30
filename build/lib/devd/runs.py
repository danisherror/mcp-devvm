"""Run records on the VM side (doc §12.2): durable before the effect starts,
`status` written LAST as the reconciliation primitive, keyed by
Idempotency-Key so a replayed request returns the original run rather than
executing anything twice.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from devd import config


@dataclass
class RunRecord:
    run_id: str
    operation_id: str
    idempotency_key: str
    principal: str
    approval_id: str
    status: str  # RUNNING | SUCCEEDED | OP_FAILED | TIMED_OUT
    started_at: float
    exit_code: int | None = None
    summary: str | None = None
    data: dict[str, Any] | None = None

    def as_response(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "operation_id": self.operation_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "data": self.data,
        }


class RunStore:
    def __init__(self, runs_dir: Path = config.RUNS_DIR):
        self._dir = runs_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "_idempotency_index.json"
        self._by_idem: dict[str, str] = {}
        if self._index_path.exists():
            self._by_idem = json.loads(self._index_path.read_text())

    def _save_index(self) -> None:
        tmp = self._index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._by_idem))
        tmp.replace(self._index_path)

    def by_idempotency_key(self, key: str) -> RunRecord | None:
        run_id = self._by_idem.get(key)
        return self.get(run_id) if run_id else None

    def create(self, *, run_id: str, operation_id: str, idempotency_key: str, principal: str, approval_id: str) -> RunRecord:
        run_dir = self._dir / run_id
        run_dir.mkdir(parents=True, exist_ok=False)  # run_id reuse is refused
        started_at = time.time()
        meta = {
            "operation_id": operation_id,
            "idempotency_key": idempotency_key,
            "principal": principal,
            "approval_id": approval_id,
            "started_at": started_at,
        }
        (run_dir / "meta.json").write_text(json.dumps(meta))
        (run_dir / "status").write_text("RUNNING")
        self._by_idem[idempotency_key] = run_id
        self._save_index()
        return RunRecord(
            run_id=run_id, operation_id=operation_id, idempotency_key=idempotency_key,
            principal=principal, approval_id=approval_id, status="RUNNING", started_at=started_at,
        )

    def write_output(self, run_id: str, *, stdout: bytes, stderr: bytes) -> None:
        run_dir = self._dir / run_id
        (run_dir / "stdout").write_bytes(stdout)
        (run_dir / "stderr").write_bytes(stderr)

    def finish(self, run_id: str, *, status: str, exit_code: int | None, summary: str | None, data: dict[str, Any] | None) -> None:
        run_dir = self._dir / run_id
        result = {"exit_code": exit_code, "summary": summary, "data": data or {}}
        (run_dir / "result.json").write_text(json.dumps(result))
        (run_dir / "status").write_text(status)  # written LAST -- reconciliation reads this

    def get(self, run_id: str) -> RunRecord | None:
        run_dir = self._dir / run_id
        meta_path = run_dir / "meta.json"
        if not meta_path.exists():
            return None
        meta = json.loads(meta_path.read_text())
        status_path = run_dir / "status"
        status = status_path.read_text().strip() if status_path.exists() else "RUNNING"
        result: dict[str, Any] = {}
        result_path = run_dir / "result.json"
        if result_path.exists():
            result = json.loads(result_path.read_text())
        return RunRecord(
            run_id=run_id,
            operation_id=meta["operation_id"],
            idempotency_key=meta["idempotency_key"],
            principal=meta["principal"],
            approval_id=meta["approval_id"],
            status=status,
            started_at=meta["started_at"],
            exit_code=result.get("exit_code"),
            summary=result.get("summary"),
            data=result.get("data"),
        )

    def read_output(self, run_id: str, stream: str, offset: int, limit: int) -> bytes:
        path = self._dir / run_id / stream
        if not path.exists():
            return b""
        return path.read_bytes()[offset : offset + limit]
