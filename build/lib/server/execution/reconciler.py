"""Resolves UNKNOWN approvals. Reads only -- never re-executes (doc §13.4,
§10.6 analogue). Runs as logically separate work from the request path (the
doc: "the reconciler runs as a separate process so a crash in the request
path never strands an UNKNOWN" -- here, within one process, it is at least a
separate asyncio task with its own queue and schedule).
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from server.approvals.store import ApprovalStore
from server.audit.logger import AuditLogger
from server.auth.tokens import TokenMinter
from server.policy.targets import Target
from server.tunnel.devd_client import client_for
from server.tunnel.manager import HostKeyMismatch, TunnelDown, TunnelManager

logger = logging.getLogger("server.reconciler")

SETTLED_STATUSES = ("SUCCEEDED", "OP_FAILED", "TIMED_OUT")


class Reconciler:
    def __init__(
        self,
        *,
        store: ApprovalStore,
        targets: dict[str, Target],
        tunnel: TunnelManager,
        tokens: TokenMinter,
        audit: AuditLogger,
        poll_interval_s: float = 5,
        max_attempts: int = 20,
    ):
        self._store = store
        self._targets = targets
        self._tunnel = tunnel
        self._tokens = tokens
        self._audit = audit
        self._poll_interval_s = poll_interval_s
        self._max_attempts = max_attempts
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run_forever())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def enqueue(self, approval_id: str) -> None:
        await self._queue.put(approval_id)

    async def _run_forever(self) -> None:
        while True:
            approval_id = await self._queue.get()
            try:
                await self._reconcile_with_retries(approval_id)
            except Exception:  # noqa: BLE001 -- the reconciler must never die
                logger.exception("reconciler failed on approval_id=%s", approval_id)

    async def _reconcile_with_retries(self, approval_id: str) -> None:
        for _ in range(self._max_attempts):
            approval = await self._store.get(approval_id)
            if approval is None or approval.status != "UNKNOWN":
                return  # already resolved (possibly by a concurrent reconcile pass)

            resolved = await self._reconcile_once(approval_id)
            if resolved:
                return
            await asyncio.sleep(self._poll_interval_s)

        approval = await self._store.get(approval_id)
        if approval is not None and approval.status == "UNKNOWN":
            await self._store.settle(approval_id, "NEEDS_HUMAN", error_code="reconcile_exhausted")
            await self._audit.emit("RUN_NEEDS_HUMAN", approval_id=approval_id)
            logger.critical("RUN_NEEDS_HUMAN approval_id=%s -- go look at the target", approval_id)

    async def _reconcile_once(self, approval_id: str) -> bool:
        approval = await self._store.get(approval_id)
        if approval is None:
            return True
        target = self._targets.get(approval.target_id)
        if target is None:
            return False

        token = self._tokens.mint(
            sub=approval.principal_id, approval_id=approval.id, operation_id=approval.operation_id,
            manifest_version=approval.manifest_version, audience=f"devd:{target.id}", ttl_seconds=60,
        )

        try:
            await self._tunnel.ensure_connected(target)
        except (HostKeyMismatch, TunnelDown):
            return False  # still can't reach it -- try again next tick

        try:
            async with client_for(target, timeout=15) as client:
                resp = await client.get(
                    f"/runs/by-idempotency-key/{approval.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except (httpx.TimeoutException, httpx.TransportError):
            return False

        if resp.status_code == 404:
            return False  # confirmed not started SO FAR -- keep polling until exhaustion

        if resp.status_code != 200:
            return False

        run = resp.json()
        status = run.get("status")
        if status in SETTLED_STATUSES:
            await self._store.settle(approval.id, status, run_id=run.get("run_id"))
            await self._audit.emit("RUN_RECONCILED", approval_id=approval.id, run_id=run.get("run_id"), outcome=status)
            return True

        return False  # still RUNNING on devd's side -- keep polling
