"""Notices approvals the out-of-band CLI (server/approvals/decide.py) has
moved to APPROVED -- a separate process writing to the same SQLite store --
and hands them to the executor. Also expires stale PENDING approvals."""

from __future__ import annotations

import asyncio
import logging

from server.approvals.store import ApprovalStore
from server.execution.executor import Executor

logger = logging.getLogger("server.dispatcher")


class Dispatcher:
    def __init__(self, *, store: ApprovalStore, executor: Executor, poll_interval_s: float = 2):
        self._store = store
        self._executor = executor
        self._poll_interval_s = poll_interval_s
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run_forever())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _run_forever(self) -> None:
        while True:
            try:
                await self._tick()
            except Exception:  # noqa: BLE001 -- the dispatcher must never die
                logger.exception("dispatcher tick failed")
            await asyncio.sleep(self._poll_interval_s)

    async def _tick(self) -> None:
        await self._store.expire_stale()
        cur = await self._store.db.execute("SELECT id FROM approvals WHERE status='APPROVED'")
        rows = await cur.fetchall()
        for row in rows:
            await self._executor.execute(row["id"])
