"""Entry point: wires every component together and runs the MCP server over
stdio. Run with: `python -m server.main`
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from scripts.ca import mint_certificate
from server.approvals.store import ApprovalStore
from server.audit.logger import AuditLogger
from server.audit.sink import AuditSink
from server.auth.roles import load_role_map
from server.auth.step_up import StepUpStore
from server.auth.tokens import TokenMinter
from server.execution.dispatcher import Dispatcher
from server.execution.executor import Executor
from server.execution.reconciler import Reconciler
from server.policy.matrix import load_policy
from server.policy.targets import load_targets
from server.registry.client import RegistryClient
from server.services.operation_service import OperationService
from server.tools import mcp_app
from server.tunnel.manager import TunnelManager

DATA_DIR = Path("data")
CONFIG_DIR = Path("config")

# Transport-safe logging (doc §18.5): stdio carries ONLY MCP JSON-RPC frames.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(name)s %(message)s")


def _make_cert_provider(ca_dir: Path, certs_dir: Path, source_address_file: Path):
    def _source_address() -> str:
        if source_address_file.exists():
            return source_address_file.read_text().strip() or "127.0.0.1"
        return "127.0.0.1"

    async def provider(target):
        out_prefix = certs_dir / f"{target.id}-tunnel-key"
        return await asyncio.to_thread(
            mint_certificate,
            ca_dir=ca_dir,
            out_prefix=out_prefix,
            principal="mcp-server",
            tunnel_user=target.ssh_user,
            ttl="+30m",
            source_address=_source_address(),
        )

    return provider


async def build() -> tuple[ApprovalStore, TunnelManager, Reconciler, Dispatcher]:
    targets = load_targets(CONFIG_DIR / "targets.yaml")
    policy = load_policy(CONFIG_DIR / "policy.yaml")
    role_map = load_role_map(CONFIG_DIR / "roles.yaml")

    if not targets:
        raise RuntimeError(f"no targets configured in {CONFIG_DIR / 'targets.yaml'}")
    target = next(iter(targets.values()))  # single-target demo (§9.2 simplification)

    store = ApprovalStore(DATA_DIR / "approvals.db")
    await store.open()

    audit = AuditLogger(AuditSink(DATA_DIR / "audit"))
    tokens = TokenMinter.from_file(DATA_DIR / "keys" / "token_signing_key.pem")
    step_up = StepUpStore(DATA_DIR / "step_up.state")

    cert_provider = _make_cert_provider(DATA_DIR / "ca", DATA_DIR / "tunnel-certs", DATA_DIR / "tunnel_source_address.txt")
    tunnel = TunnelManager(pin_dir=DATA_DIR / "known_hosts", cert_provider=cert_provider)

    registry = RegistryClient(tokens, tunnel)

    reconciler = Reconciler(store=store, targets=targets, tunnel=tunnel, tokens=tokens, audit=audit)
    reconciler.start()

    executor = Executor(
        store=store, targets=targets, policy=policy, registry=registry, tunnel=tunnel,
        tokens=tokens, audit=audit, reconciler_enqueue=reconciler.enqueue, role_map=role_map,
    )

    dispatcher = Dispatcher(store=store, executor=executor)
    dispatcher.start()

    service = OperationService(
        store=store, target=target, policy=policy, registry=registry, tunnel=tunnel,
        tokens=tokens, audit=audit, executor=executor, reconciler=reconciler, step_up=step_up,
    )
    mcp_app.bind(service, role_map)

    return store, tunnel, reconciler, dispatcher


async def _amain() -> None:
    store, tunnel, reconciler, dispatcher = await build()
    try:
        await mcp_app.mcp.run_stdio_async()
    finally:
        await dispatcher.stop()
        await reconciler.stop()
        await tunnel.close_all()
        await store.close()


if __name__ == "__main__":
    asyncio.run(_amain())
