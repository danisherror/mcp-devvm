"""Integration tests against the real dev-VM container (doc §25.3). These
require the container from `python scripts/setup_dev_vm.py` to be running
and reachable -- they are skipped automatically otherwise.

Run: python scripts/setup_dev_vm.py && pytest tests/integration -q
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from server.approvals.store import ApprovalStore
from server.audit.logger import AuditLogger
from server.audit.sink import AuditSink
from server.auth.principal import Principal
from server.auth.step_up import StepUpStore
from server.auth.tokens import TokenMinter
from server.execution.dispatcher import Dispatcher
from server.execution.executor import Executor
from server.execution.reconciler import Reconciler
from server.policy.matrix import load_policy
from server.policy.targets import load_targets
from server.registry.client import RegistryClient
from server.services.operation_service import OperationService
from server.tunnel.manager import TunnelManager
from scripts.ca import mint_certificate

ROOT = Path(__file__).resolve().parent.parent.parent
CONTAINER = "mcp-devvm-dev-vm"


def _container_running() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


pytestmark = pytest.mark.skipif(
    not _container_running(),
    reason="dev-VM container not running -- run `python scripts/setup_dev_vm.py` first",
)


@pytest.fixture
async def app(tmp_path):
    targets = load_targets(ROOT / "config" / "targets.yaml")
    policy = load_policy(ROOT / "config" / "policy.yaml")
    target = next(iter(targets.values()))

    store = ApprovalStore(tmp_path / "approvals.db")
    await store.open()

    audit = AuditLogger(AuditSink(tmp_path / "audit"))
    tokens = TokenMinter.from_file(ROOT / "data" / "keys" / "token_signing_key.pem")
    step_up = StepUpStore(tmp_path / "step_up.state")

    source_addr_file = ROOT / "data" / "tunnel_source_address.txt"
    source_address = source_addr_file.read_text().strip() if source_addr_file.exists() else "127.0.0.1"

    async def cert_provider(target):
        import asyncio
        return await asyncio.to_thread(
            mint_certificate, ca_dir=ROOT / "data" / "ca", out_prefix=tmp_path / f"{target.id}-key",
            principal="pytest", tunnel_user=target.ssh_user, ttl="+10m", source_address=source_address,
        )

    tunnel = TunnelManager(pin_dir=tmp_path / "known_hosts", cert_provider=cert_provider)
    registry = RegistryClient(tokens, tunnel)

    reconciler = Reconciler(store=store, targets=targets, tunnel=tunnel, tokens=tokens, audit=audit, poll_interval_s=1, max_attempts=5)
    reconciler.start()

    executor = Executor(store=store, targets=targets, policy=policy, registry=registry, tunnel=tunnel,
                         tokens=tokens, audit=audit, reconciler_enqueue=reconciler.enqueue,
                         role_map={"pytest-user": ("developer", "tech-lead")})

    dispatcher = Dispatcher(store=store, executor=executor, poll_interval_s=0.5)
    dispatcher.start()

    service = OperationService(store=store, target=target, policy=policy, registry=registry, tunnel=tunnel,
                                tokens=tokens, audit=audit, executor=executor, reconciler=reconciler, step_up=step_up)

    yield service, store, executor

    await dispatcher.stop()
    await reconciler.stop()
    await tunnel.close_all()
    await store.close()


PRINCIPAL = Principal(user_id="pytest-user", display_name="pytest", roles=("developer", "tech-lead"))


async def _approve(store: ApprovalStore, approval_id: str) -> None:
    approval = await store.get(approval_id)
    await store.record_decision(approval_id=approval_id, decided_by="pytest-approver",
                                 decision="APPROVE", displayed_hash=approval.proposal_hash, channel="test")


async def _wait_for_terminal(store: ApprovalStore, approval_id: str, timeout_s: float = 10) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        approval = await store.get(approval_id)
        if approval.status not in ("PENDING", "APPROVED", "CLAIMED", "RUNNING", "UNKNOWN"):
            return approval.status
        await __import__("asyncio").sleep(0.2)
    raise TimeoutError(f"approval {approval_id} never reached a terminal state")


class TestReadOnly:
    async def test_git_status_direct(self, app):
        service, _store, _executor = app
        result = await service.run_operation(PRINCIPAL, "git.status", {"repo": "api"})
        assert result["status"] == "SUCCEEDED"
        assert "branch" in result["data"]

    async def test_logs_tail_direct(self, app):
        service, _store, _executor = app
        result = await service.run_operation(PRINCIPAL, "logs.tail", {"lines": 3})
        assert result["status"] == "SUCCEEDED"
        assert "lines" in result["data"]


class TestFullApprovalCycle:
    async def test_propose_approve_execute_mutating(self, app):
        service, store, _executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "web", "branch": "master"}, "integration test",
        )
        assert proposal["status"] == "PENDING"
        await _approve(store, proposal["approval_id"])
        status = await _wait_for_terminal(store, proposal["approval_id"])
        assert status == "SUCCEEDED"

    async def test_service_restart_requires_step_up(self, app):
        service, _store, _executor = app
        with pytest.raises(Exception, match="reauthentication_required"):
            await service.request_operation(PRINCIPAL, "service.restart", {"service": "web"}, "test")


class TestManifestVersioning:
    async def test_manifest_version_mismatch_goes_stale(self, app):
        """Simulates a devd redeploy between approval and execution by
        tampering with the stored manifest_version after proposal (doc's
        actual scenario is a real redeploy; this reaches the same code path
        without needing to rebuild the container mid-test)."""
        service, store, _executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.status", {"repo": "api"}, "test",
        )
        # git.status is READ_ONLY + approval not required, so it executes
        # directly and never reaches an approval record -- use git.checkout
        # instead, which does.
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "api", "branch": "master"}, "test",
        )
        approval_id = proposal["approval_id"]
        await store.db.execute("UPDATE approvals SET manifest_version = 999 WHERE id = ?", (approval_id,))
        await store.db.commit()
        await _approve(store, approval_id)
        status = await _wait_for_terminal(store, approval_id)
        assert status == "STALE"


class TestFaultInjection:
    async def test_transport_timeout_yields_unknown_then_reconciler_resolves_it(self, app, monkeypatch):
        """doc §13.4/§25.5: a dropped connection is UNKNOWN, never reported as
        failure, and the reconciler -- not a retry of the mutating call --
        is what resolves it, by reading devd's own idempotency-keyed record."""
        import httpx

        service, store, executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "api", "branch": "master"}, "fault injection test",
        )
        await _approve(store, proposal["approval_id"])

        approval_before = await store.get(proposal["approval_id"])
        assert approval_before.status == "APPROVED"

        # Force the executor's POST to devd to look like a dropped connection,
        # WITHOUT touching devd itself -- the real request never completes,
        # so devd may or may not have started the operation by the time this
        # raises, exactly like a real dropped tunnel.
        import server.execution.executor as executor_module

        real_client_for = executor_module.client_for

        class _DyingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **kw):
                raise httpx.TransportError("simulated tunnel drop")

        def _fake_client_for(target, timeout=30):
            return _DyingClient()

        monkeypatch.setattr(executor_module, "client_for", _fake_client_for)
        try:
            outcome = await executor.execute(proposal["approval_id"])
        finally:
            monkeypatch.setattr(executor_module, "client_for", real_client_for)

        assert outcome == "UNKNOWN"
        mid = await store.get(proposal["approval_id"])
        assert mid.status == "UNKNOWN"

        # The reconciler (already running from the fixture) should resolve
        # it shortly via devd's own idempotency-keyed run record -- devd
        # never actually received this particular call, so it should settle
        # as NEEDS_HUMAN once the reconciler exhausts its retries, NOT as if
        # it had silently succeeded or been retried.
        status = await _wait_for_terminal(store, proposal["approval_id"], timeout_s=15)
        assert status == "NEEDS_HUMAN"


class TestIdempotency:
    async def test_double_claim_executes_exactly_once(self, app):
        service, store, executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "web", "branch": "master"}, "test",
        )
        await _approve(store, proposal["approval_id"])
        # Let the dispatcher's own tick claim and execute it first.
        status = await _wait_for_terminal(store, proposal["approval_id"])
        assert status == "SUCCEEDED"
        # A second, direct claim attempt on the same (now-settled) approval must no-op.
        result = await executor.execute(proposal["approval_id"])
        assert result == "noop"
