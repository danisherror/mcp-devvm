"""The control-plane store (doc §16): SQLite (WAL, BEGIN IMMEDIATE) is
adequate for the local topology per the doc -- Postgres for the remote one.
In-memory state is explicitly NOT an implementation of single-use; this is.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite

from common.approval_sig import required_approvers
from server.approvals.state_machine import IllegalTransition, validate_transition

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
  id                  TEXT PRIMARY KEY,
  request_id          TEXT NOT NULL,
  principal_id        TEXT NOT NULL,
  target_id           TEXT NOT NULL,
  operation_id        TEXT NOT NULL,
  manifest_version    INTEGER NOT NULL,
  manifest_hash       TEXT NOT NULL,
  params              TEXT NOT NULL,
  preconditions       TEXT NOT NULL DEFAULT '{}',
  risk_class          TEXT NOT NULL,
  effect_summary      TEXT NOT NULL,
  reason              TEXT,
  proposal_hash       TEXT NOT NULL,
  approved_hash       TEXT,
  approvals_required  INTEGER NOT NULL DEFAULT 1,
  status              TEXT NOT NULL DEFAULT 'PENDING',
  created_at          REAL NOT NULL,
  expires_at          REAL NOT NULL,
  approved_expires_at REAL,
  decided_at          REAL,
  claimed_at          REAL,
  claimed_by          TEXT,
  run_id              TEXT,
  settled_at          REAL,
  outcome             TEXT,
  error_code          TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_principal_status ON approvals (principal_id, status);
CREATE INDEX IF NOT EXISTS idx_approvals_pending ON approvals (status, expires_at);

CREATE TABLE IF NOT EXISTS approval_decisions (
  id             TEXT PRIMARY KEY,
  approval_id    TEXT NOT NULL REFERENCES approvals(id),
  decided_by     TEXT NOT NULL,
  decision       TEXT NOT NULL CHECK (decision IN ('APPROVE','DENY')),
  decided_at     REAL NOT NULL,
  displayed_hash TEXT NOT NULL,
  channel        TEXT NOT NULL,
  signature      TEXT,
  UNIQUE (approval_id, decided_by)
);
"""


@dataclass
class Approval:
    id: str
    request_id: str
    principal_id: str
    target_id: str
    operation_id: str
    manifest_version: int
    manifest_hash: str
    params: dict[str, Any]
    preconditions: dict[str, Any]
    risk_class: str
    effect_summary: dict[str, Any]
    reason: str
    proposal_hash: str
    approvals_required: int
    status: str
    created_at: float
    expires_at: float
    approved_hash: str | None
    approved_expires_at: float | None
    claimed_by: str | None
    run_id: str | None
    outcome: str | None
    error_code: str | None

    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> "Approval":
        return cls(
            id=row["id"], request_id=row["request_id"], principal_id=row["principal_id"],
            target_id=row["target_id"], operation_id=row["operation_id"],
            manifest_version=row["manifest_version"], manifest_hash=row["manifest_hash"],
            params=json.loads(row["params"]), preconditions=json.loads(row["preconditions"]),
            risk_class=row["risk_class"], effect_summary=json.loads(row["effect_summary"]),
            reason=row["reason"], proposal_hash=row["proposal_hash"],
            approvals_required=row["approvals_required"], status=row["status"],
            created_at=row["created_at"], expires_at=row["expires_at"],
            approved_hash=row["approved_hash"], approved_expires_at=row["approved_expires_at"],
            claimed_by=row["claimed_by"], run_id=row["run_id"], outcome=row["outcome"],
            error_code=row["error_code"],
        )


class ApprovalStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None
        # aiosqlite serializes statements from a single shared connection onto
        # one worker thread, but a multi-statement "BEGIN IMMEDIATE ... COMMIT"
        # transaction is still two separate awaited calls -- without this lock,
        # a second coroutine's BEGIN can interleave between them and hit
        # "cannot start a transaction within a transaction". The lock makes the
        # CAS body atomic with respect to other tasks in this process; SQLite's
        # own locking is what makes it safe across processes.
        self._claim_lock = asyncio.Lock()

    async def open(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.executescript(SCHEMA)
        await self._migrate()
        await self._db.commit()

    async def _migrate(self) -> None:
        # Stores created before signed approvals existed lack this column.
        cur = await self.db.execute("PRAGMA table_info(approval_decisions)")
        columns = {row["name"] for row in await cur.fetchall()}
        if "signature" not in columns:
            await self.db.execute("ALTER TABLE approval_decisions ADD COLUMN signature TEXT")

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "ApprovalStore.open() was not called"
        return self._db

    async def create(
        self, *, principal_id: str, request_id: str, target_id: str, operation_id: str,
        manifest_version: int, manifest_hash: str, params: dict[str, Any], preconditions: dict[str, Any],
        risk_class: str, effect_summary: dict[str, Any], reason: str, proposal_hash: str,
        approvals_required: int, ttl_seconds: float,
    ) -> Approval:
        now = time.time()
        approval_id = "appr_" + uuid.uuid4().hex[:16]
        await self.db.execute(
            "INSERT INTO approvals (id, request_id, principal_id, target_id, operation_id, manifest_version, "
            "manifest_hash, params, preconditions, risk_class, effect_summary, reason, proposal_hash, "
            "approvals_required, status, created_at, expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'PENDING', ?,?)",
            (
                approval_id, request_id, principal_id, target_id, operation_id, manifest_version, manifest_hash,
                json.dumps(params), json.dumps(preconditions), risk_class, json.dumps(effect_summary), reason,
                proposal_hash, approvals_required, now, now + ttl_seconds,
            ),
        )
        await self.db.commit()
        approval = await self.get(approval_id)
        assert approval is not None
        return approval

    async def get(self, approval_id: str) -> Approval | None:
        cur = await self.db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        row = await cur.fetchone()
        return Approval.from_row(row) if row else None

    async def list_pending_for(self, principal_id: str) -> list[Approval]:
        cur = await self.db.execute(
            "SELECT * FROM approvals WHERE principal_id = ? AND status = 'PENDING' ORDER BY created_at DESC",
            (principal_id,),
        )
        rows = await cur.fetchall()
        return [Approval.from_row(r) for r in rows]

    async def record_decision(
        self, *, approval_id: str, decided_by: str, decision: str, displayed_hash: str, channel: str,
        signature: dict[str, Any] | None = None,
    ) -> Approval:
        """`signature` is the approver's SignedApproval (common/approval_sig.py).
        The store doesn't verify it -- devd does, at execution time, because
        anything on this host can write this table."""
        approval = await self.get(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        if approval.status != "PENDING":
            raise IllegalTransition(f"cannot decide on approval in status {approval.status}")
        if time.time() > approval.expires_at:
            await self._set_status_unchecked(approval_id, "EXPIRED")
            raise IllegalTransition("decision window elapsed")
        if (decision == "APPROVE" and decided_by == approval.principal_id
                and required_approvers(approval.risk_class, approval.approvals_required) > 1):
            # devd refuses these signatures too (common/approval_sig.py).
            raise IllegalTransition("requester cannot approve a four-eyes request")

        decision_id = "dec_" + uuid.uuid4().hex[:16]
        try:
            await self.db.execute(
                "INSERT INTO approval_decisions (id, approval_id, decided_by, decision, decided_at, "
                "displayed_hash, channel, signature) VALUES (?,?,?,?,?,?,?,?)",
                (decision_id, approval_id, decided_by, decision, time.time(), displayed_hash, channel,
                 json.dumps(signature) if signature is not None else None),
            )
            await self.db.commit()
        except aiosqlite.IntegrityError:
            # UNIQUE(approval_id, decided_by): the same human deciding twice counts once (§8.1).
            result = await self.get(approval_id)
            assert result is not None
            return result

        if decision == "DENY":
            await self._set_status_unchecked(approval_id, "DENIED")
            result = await self.get(approval_id)
            assert result is not None
            return result

        cur = await self.db.execute(
            "SELECT COUNT(DISTINCT decided_by) AS n FROM approval_decisions "
            "WHERE approval_id = ? AND decision = 'APPROVE'",
            (approval_id,),
        )
        row = await cur.fetchone()
        approve_count = row["n"]

        if approve_count >= approval.approvals_required:
            approved_expires_at = time.time() + 120  # execution window
            await self.db.execute(
                "UPDATE approvals SET status='APPROVED', approved_hash=?, approved_expires_at=?, decided_at=? "
                "WHERE id=? AND status='PENDING'",
                (displayed_hash, approved_expires_at, time.time(), approval_id),
            )
            await self.db.commit()

        result = await self.get(approval_id)
        assert result is not None
        return result

    async def signatures_for(self, approval_id: str) -> list[dict[str, Any]]:
        cur = await self.db.execute(
            "SELECT signature FROM approval_decisions WHERE approval_id = ? AND decision = 'APPROVE' "
            "AND signature IS NOT NULL ORDER BY decided_at",
            (approval_id,),
        )
        return [json.loads(row["signature"]) for row in await cur.fetchall()]

    async def _set_status_unchecked(self, approval_id: str, status: str) -> None:
        await self.db.execute("UPDATE approvals SET status=? WHERE id=?", (status, approval_id))
        await self.db.commit()

    async def set_status(self, approval_id: str, status: str) -> None:
        current = await self.get(approval_id)
        if current is None:
            raise KeyError(approval_id)
        validate_transition(current.status, status)
        await self._set_status_unchecked(approval_id, status)

    async def claim(self, approval_id: str, *, worker_id: str) -> Approval | None:
        """Atomic CAS: APPROVED -> CLAIMED. Win -> exactly one execution
        attempt. Lose -> no-op, caller reads the settled record instead."""
        async with self._claim_lock:
            await self.db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self.db.execute(
                    "UPDATE approvals SET status='CLAIMED', claimed_by=?, claimed_at=? "
                    "WHERE id=? AND status='APPROVED' AND approved_expires_at > ?",
                    (worker_id, time.time(), approval_id, time.time()),
                )
                await self.db.commit()
            except Exception:
                await self.db.rollback()
                raise
            if cur.rowcount == 0:
                return None
            return await self.get(approval_id)

    async def settle(
        self, approval_id: str, outcome: str, *, run_id: str | None = None, error_code: str | None = None
    ) -> None:
        current = await self.get(approval_id)
        if current is None:
            raise KeyError(approval_id)
        validate_transition(current.status, outcome)
        await self.db.execute(
            "UPDATE approvals SET status=?, outcome=?, run_id=COALESCE(?, run_id), settled_at=?, error_code=? "
            "WHERE id=?",
            (outcome, outcome, run_id, time.time(), error_code, approval_id),
        )
        await self.db.commit()

    async def expire_stale(self) -> int:
        now = time.time()
        cur = await self.db.execute(
            "UPDATE approvals SET status='EXPIRED' WHERE status='PENDING' AND expires_at < ?", (now,)
        )
        await self.db.commit()
        return cur.rowcount

    async def count_recent(self, principal_id: str, target_id: str, since_seconds: float) -> int:
        cur = await self.db.execute(
            "SELECT COUNT(*) AS n FROM approvals WHERE principal_id=? AND target_id=? AND created_at > ?",
            (principal_id, target_id, time.time() - since_seconds),
        )
        row = await cur.fetchone()
        return row["n"]

    async def list_unresolved(self) -> list[Approval]:
        cur = await self.db.execute("SELECT * FROM approvals WHERE status = 'UNKNOWN'")
        rows = await cur.fetchall()
        return [Approval.from_row(r) for r in rows]
