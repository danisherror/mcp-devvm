"""claim -> intent -> re-verify -> token -> call devd -> triage -> outcome
(doc §7.3, §13.1). This is the module where the whole pipeline's guarantees
actually get exercised in sequence.
"""

from __future__ import annotations

from typing import Awaitable, Callable

import httpx

from server.approvals.store import Approval, ApprovalStore
from server.audit.logger import AuditLogger
from server.auth.principal import Principal
from server.auth.roles import resolve_roles
from server.auth.tokens import TokenMinter
from server.execution.triage import triage_error_code, triage_response
from server.policy.matrix import PolicyMatrix
from server.policy.targets import Target
from server.proposals.engine import recompute_proposal_hash
from server.registry.client import RegistryClient
from server.tunnel.devd_client import client_for
from server.tunnel.manager import HostKeyMismatch, TunnelDown, TunnelManager

WORKER_ID = "executor-1"

ReconcilerEnqueue = Callable[[str], Awaitable[None]]


class Executor:
    def __init__(
        self,
        *,
        store: ApprovalStore,
        targets: dict[str, Target],
        policy: PolicyMatrix,
        registry: RegistryClient,
        tunnel: TunnelManager,
        tokens: TokenMinter,
        audit: AuditLogger,
        reconciler_enqueue: ReconcilerEnqueue,
        role_map: dict[str, tuple[str, ...]] | None = None,
    ):
        self._store = store
        self._targets = targets
        self._policy = policy
        self._registry = registry
        self._tunnel = tunnel
        self._tokens = tokens
        self._audit = audit
        self._reconciler_enqueue = reconciler_enqueue
        self._role_map = role_map or {}

    async def execute(self, approval_id: str) -> str:
        approval = await self._store.claim(approval_id, worker_id=WORKER_ID)
        if approval is None:
            return "noop"

        await self._audit.emit(
            "EXECUTION_INTENT", approval_id=approval.id, operation_id=approval.operation_id,
            manifest_version=approval.manifest_version, target_id=approval.target_id, params=approval.params,
        )

        # Recompute from the stored fields rather than trusting the stored
        # hash columns, so a post-approval edit to params/preconditions is caught.
        recomputed = recompute_proposal_hash(approval)
        if recomputed is None or not (approval.approved_hash == approval.proposal_hash == recomputed):
            await self._audit.emit("SECURITY_HASH_MISMATCH", approval_id=approval.id)
            return await self._settle(approval, "UNAUTHORIZED", error_code="hash_mismatch")

        target = self._targets.get(approval.target_id)
        if target is None:
            return await self._settle(approval, "UNAUTHORIZED", error_code="unknown_target")

        # Re-derive the principal and re-check policy -- it may have changed since approval.
        principal = Principal(
            user_id=approval.principal_id, display_name=approval.principal_id,
            roles=resolve_roles(approval.principal_id, self._role_map),
        )
        try:
            op = await self._registry.get(target, approval.operation_id, principal.user_id, force_refresh=True)
        except Exception:  # noqa: BLE001 -- registry unreachable
            return await self._settle(approval, "UNREACHABLE", error_code="registry_unreachable")

        if op is None or not self._policy.allows(principal, target.id, op):
            return await self._settle(approval, "UNAUTHORIZED", error_code="policy_changed")

        if (op.version, op.content_hash) != (approval.manifest_version, approval.manifest_hash):
            return await self._settle(approval, "STALE", error_code="manifest_changed")

        await self._store.set_status(approval.id, "RUNNING")

        token = self._tokens.mint(
            sub=principal.user_id, approval_id=approval.id, operation_id=op.id,
            manifest_version=op.version, audience=f"devd:{target.id}", ttl_seconds=120,
        )

        try:
            await self._tunnel.ensure_connected(target)
        except HostKeyMismatch:
            await self._audit.emit("SSH_HOST_KEY_MISMATCH", approval_id=approval.id, target_id=target.id)
            return await self._settle(approval, "UNREACHABLE", error_code="host_key_mismatch")
        except TunnelDown as exc:
            return await self._settle(approval, "UNREACHABLE", error_code=str(exc))

        try:
            async with client_for(target, timeout=op.sandbox.timeout_s + 15) as client:
                resp = await client.post(
                    f"/operations/{op.id}/run",
                    json={
                        "params": approval.params,
                        "preconditions": approval.preconditions,
                        "manifest_version": op.version,
                        "manifest_hash": op.content_hash,
                    },
                    headers={"Authorization": f"Bearer {token}", "Idempotency-Key": approval.id},
                )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            # NOT failure -- devd may have accepted the request and be running it.
            await self._store.set_status(approval.id, "UNKNOWN")
            await self._audit.emit("RUN_UNKNOWN", approval_id=approval.id, error=type(exc).__name__)
            await self._reconciler_enqueue(approval.id)
            return "UNKNOWN"

        outcome = triage_response(resp)
        run_id = None
        try:
            run_id = resp.json().get("run_id")
        except Exception:  # noqa: BLE001
            pass

        if outcome == "UNKNOWN":
            await self._store.set_status(approval.id, "UNKNOWN")
            await self._audit.emit("RUN_UNKNOWN", approval_id=approval.id, devd_status=resp.status_code)
            await self._reconciler_enqueue(approval.id)
            return outcome

        return await self._settle(approval, outcome, run_id=run_id, error_code=triage_error_code(resp), devd_status=resp.status_code)

    async def _settle(
        self, approval: Approval, outcome: str, *, run_id: str | None = None,
        error_code: str | None = None, devd_status: int | None = None,
    ) -> str:
        await self._store.settle(approval.id, outcome, run_id=run_id, error_code=error_code)
        await self._audit.emit(
            "EXECUTION_OUTCOME", approval_id=approval.id, run_id=run_id, outcome=outcome,
            error_code=error_code, devd_status=devd_status,
        )
        return outcome
