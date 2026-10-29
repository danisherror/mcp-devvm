"""Integration tests against the real dev-VM container (doc §25.3). These
require the container from `python scripts/setup_dev_vm.py` to be running
and reachable -- they are skipped automatically otherwise.

Run: python scripts/setup_dev_vm.py && pytest tests/integration -q
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import approver_user, effect_hash, sign_approval
from server.proposals.engine import recompute_proposal_hash

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


APPROVERS_PUBLIC = ROOT / "data" / "approvers" / "public"


@pytest.fixture
def approver():
    """A throwaway approver key, trusted by the running devd only for the
    length of one test: the public half goes into the mounted approvers
    directory and is removed afterwards; the private half never leaves
    memory."""
    name = f"pytest-{uuid.uuid4().hex[:8]}"
    key = Ed25519PrivateKey.generate()
    APPROVERS_PUBLIC.mkdir(parents=True, exist_ok=True)
    pub = APPROVERS_PUBLIC / f"{name}.pub"
    pub.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    yield name, key
    pub.unlink(missing_ok=True)


@pytest.fixture
async def app(tmp_path, approver):
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

    service = OperationService(store=store, targets=targets, policy=policy, registry=registry, tunnel=tunnel,
                                tokens=tokens, audit=audit, executor=executor, reconciler=reconciler, step_up=step_up)

    global _APPROVER
    _APPROVER = approver
    yield service, store, executor
    _APPROVER = None

    await dispatcher.stop()
    await reconciler.stop()
    await tunnel.close_all()
    await store.close()


PRINCIPAL = Principal(user_id="pytest-user", display_name="pytest", roles=("developer", "tech-lead"))


_APPROVER = None


async def _approve(store: ApprovalStore, approval_id: str) -> None:
    """What `decide approve` does, minus the prompts: recompute the hash
    from the stored fields and sign it with the approver key."""
    name, key = _APPROVER
    approval = await store.get(approval_id)
    h = recompute_proposal_hash(approval)
    signed = sign_approval(key, approver=name, approval_id=approval_id, proposal_hash=h,
                           effect_hash=effect_hash(approval.effect_summary))
    await store.record_decision(approval_id=approval_id, decided_by=approver_user(name), decision="APPROVE",
                                 displayed_hash=h, channel="test", signature=signed.as_dict())


async def _forge_approval(store: ApprovalStore, approval_id: str) -> None:
    """What an agent with a shell could do: mark the row approved in the DB
    by hand, with no human signature."""
    approval = await store.get(approval_id)
    await store.record_decision(approval_id=approval_id, decided_by="os:agent", decision="APPROVE",
                                 displayed_hash=approval.proposal_hash, channel="forged")


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
        """Simulates a devd redeploy between proposal and execution: the
        stored proposal is rewritten as if it had been made against manifest
        v999, with its hash recomputed to match, so it reads as an honest
        old proposal rather than a tampered one (doc's actual scenario is a
        real redeploy; this reaches the same code path without rebuilding
        the container mid-test)."""
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
        old = recompute_proposal_hash(await store.get(approval_id))
        await store.db.execute("UPDATE approvals SET proposal_hash = ? WHERE id = ?", (old, approval_id))
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


class TestApprovalSignatures:
    async def test_forged_db_approval_is_refused_by_devd(self, app):
        """Gap #4: the server-side checks all pass for a hand-written DB row,
        so devd's own signature check is what stops it."""
        service, store, _executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "web", "branch": "master"}, "forgery test",
        )
        await _forge_approval(store, proposal["approval_id"])
        status = await _wait_for_terminal(store, proposal["approval_id"])
        assert status == "UNAUTHORIZED"
        approval = await store.get(proposal["approval_id"])
        assert approval.error_code.startswith("approval_signature_invalid")

    async def test_tampered_effect_text_is_refused_by_devd(self, app):
        """The human signs the effect text they were shown; if the DB copy
        was altered to describe something harmless, devd's own rendering
        won't match it."""
        import json

        service, store, _executor = app
        proposal = await service.request_operation(
            PRINCIPAL, "git.checkout", {"repo": "web", "branch": "master"}, "effect tamper test",
        )
        fake = dict(proposal["effect"], description="Does nothing at all.")
        await store.db.execute("UPDATE approvals SET effect_summary = ? WHERE id = ?",
                               (json.dumps(fake), proposal["approval_id"]))
        await store.db.commit()
        await _approve(store, proposal["approval_id"])
        status = await _wait_for_terminal(store, proposal["approval_id"])
        assert status == "UNAUTHORIZED"


class TestTunnelAccountScope:
    """Gap #1: the tunnel account must reach devd's socket and nothing else."""

    async def _connect(self, tmp_path):
        import asyncio

        import asyncssh

        targets = load_targets(ROOT / "config" / "targets.yaml")
        target = next(iter(targets.values()))
        source_addr_file = ROOT / "data" / "tunnel_source_address.txt"
        source_address = source_addr_file.read_text().strip() if source_addr_file.exists() else "127.0.0.1"
        priv, cert = await asyncio.to_thread(
            mint_certificate, ca_dir=ROOT / "data" / "ca", out_prefix=tmp_path / "scope-key",
            principal="pytest", tunnel_user=target.ssh_user, ttl="+5m", source_address=source_address,
        )
        return await asyncssh.connect(
            host=target.ssh_host, port=target.ssh_port, username=target.ssh_user,
            client_keys=asyncssh.load_keypairs([str(priv)], certlist=[str(cert)]),
            known_hosts=None, agent_path=None, config=None, connect_timeout=10,
        )

    async def test_tcp_forwarding_is_refused(self, tmp_path):
        import asyncssh

        conn = await self._connect(tmp_path)
        try:
            with pytest.raises(asyncssh.ChannelOpenError):
                await conn.open_connection("127.0.0.1", 22)
        finally:
            conn.close()

    async def test_streamlocal_forwarding_is_refused(self, tmp_path):
        import asyncssh

        conn = await self._connect(tmp_path)
        try:
            with pytest.raises(asyncssh.ChannelOpenError):
                await conn.open_unix_connection("/run/devd/devd.sock")
        finally:
            conn.close()

    async def test_any_command_only_reaches_devd(self, tmp_path):
        conn = await self._connect(tmp_path)
        try:
            result = await conn.run("id; cat /etc/passwd", input="GET /manifest HTTP/1.0\r\n\r\n", timeout=15)
            assert "uid=" not in result.stdout
            assert "root:" not in result.stdout
            assert result.stdout.startswith("HTTP/1.")  # devd answered (401: no token)
        finally:
            conn.close()
