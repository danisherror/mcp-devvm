"""The human decision path -- deliberately NOT an MCP tool (doc §7.2, §24).

Usage:
    python -m server.approvals.decide list
    python -m server.approvals.decide show <approval_id>
    python -m server.approvals.decide approve <approval_id>
    python -m server.approvals.decide deny <approval_id> [--reason TEXT]

This CLI is the out-of-band channel the agent cannot reach (B4). It reads
and writes the same SQLite approval store the MCP server uses, so it must be
run against the same `data/approvals.db` the server was started with.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from server.approvals.store import Approval, ApprovalStore
from server.auth.principal import resolve_local_principal

DB_PATH = Path("data/approvals.db")

HIGH_RISK = {"DESTRUCTIVE", "PRIVILEGE"}


def _render(approval: Approval, *, rate_hint: str | None = None) -> str:
    lines: list[str] = []
    effect = approval.effect_summary
    lines.append(f"approval_id   {approval.id}")
    lines.append(f"hash          {approval.proposal_hash[:12]}")
    lines.append(f"requested_by  {approval.principal_id}")
    lines.append(f"target        {approval.target_id}")
    lines.append(f"operation     {approval.operation_id}  (manifest v{approval.manifest_version})")
    lines.append(f"risk          {approval.risk_class}" + ("   *** HIGH RISK ***" if approval.risk_class in HIGH_RISK else ""))
    lines.append("")
    lines.append("effect:")
    lines.append(f"  description : {effect.get('description', '')}")
    lines.append(f"  writes      : {effect.get('writes', [])}")
    lines.append(f"  reads       : {effect.get('reads', [])}")
    lines.append(f"  network     : {effect.get('network', [])}")
    lines.append(f"  services    : {effect.get('services', [])}")
    lines.append("")
    lines.append("params:")
    for k, v in approval.params.items():
        lines.append(f"  {k} = {v!r}")
    lines.append("")
    lines.append("preconditions asserted at proposal time:")
    for k, v in approval.preconditions.items():
        lines.append(f"  {k} = {v!r}")
    lines.append("")
    if approval.reason:
        lines.append(f"reason: {approval.reason}")
    lines.append(f"expires_at (decision window): {approval.expires_at}")
    if approval.approvals_required > 1:
        lines.append(f"four-eyes: {approval.approvals_required} distinct approvals required")
    if rate_hint:
        lines.append(rate_hint)
    return "\n".join(lines)


async def _list(store: ApprovalStore, principal_id: str | None) -> None:
    if principal_id:
        approvals = await store.list_pending_for(principal_id)
    else:
        # CLI operator view: show everything pending, not just one's own.
        cur = await store.db.execute("SELECT id FROM approvals WHERE status='PENDING' ORDER BY created_at DESC")
        rows = await cur.fetchall()
        approvals = [a for a in (await store.get(r["id"]) for r in rows) if a is not None]
    if not approvals:
        print("no pending approvals")
        return
    for a in approvals:
        marker = " *** HIGH RISK ***" if a.risk_class in HIGH_RISK else ""
        print(f"{a.id}  {a.operation_id:<20} {a.risk_class:<16} requested_by={a.principal_id}{marker}")


async def _show(store: ApprovalStore, approval_id: str) -> None:
    approval = await store.get(approval_id)
    if approval is None:
        print(f"no such approval: {approval_id}", file=sys.stderr)
        raise SystemExit(1)
    recent = await store.count_recent(approval.principal_id, approval.target_id, since_seconds=300)
    print(_render(approval, rate_hint=f"rate: {recent} operation(s) proposed by this principal in the last 5 minutes"))


async def _approve(store: ApprovalStore, approval_id: str, decided_by: str) -> None:
    approval = await store.get(approval_id)
    if approval is None:
        print(f"no such approval: {approval_id}", file=sys.stderr)
        raise SystemExit(1)

    print(_render(approval))
    print()

    if approval.risk_class in HIGH_RISK:
        # Typed confirmation for high-risk operations, not a checkbox (§19.1/§23.1).
        typed = input(f"Type the approval id ({approval.id}) to confirm this {approval.risk_class} operation: ")
        if typed.strip() != approval.id:
            print("confirmation did not match -- not approved")
            raise SystemExit(1)
    else:
        # Default focus is Deny: an explicit "approve" is required, no bare Enter.
        typed = input("Type 'approve' to proceed, anything else to abort: ")
        if typed.strip().lower() != "approve":
            print("aborted -- not approved")
            raise SystemExit(1)

    # displayed_hash: the hash of exactly what was rendered above -- since the
    # render is reconstructed straight from the stored proposal fields, this
    # IS that hash; there is no separate re-render step that could diverge.
    result = await store.record_decision(
        approval_id=approval.id, decided_by=decided_by, decision="APPROVE",
        displayed_hash=approval.proposal_hash, channel="cli",
    )
    print(f"status: {result.status}")
    if result.status == "PENDING":
        print("(waiting on additional approvers -- four-eyes not yet satisfied)")


async def _deny(store: ApprovalStore, approval_id: str, decided_by: str, reason: str | None) -> None:
    approval = await store.get(approval_id)
    if approval is None:
        print(f"no such approval: {approval_id}", file=sys.stderr)
        raise SystemExit(1)
    result = await store.record_decision(
        approval_id=approval.id, decided_by=decided_by, decision="DENY",
        displayed_hash=approval.proposal_hash, channel="cli",
    )
    print(f"status: {result.status}")


async def _main() -> None:
    parser = argparse.ArgumentParser(prog="python -m server.approvals.decide")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--mine", action="store_true", help="only show approvals requested by the current principal")

    p_show = sub.add_parser("show")
    p_show.add_argument("approval_id")

    p_approve = sub.add_parser("approve")
    p_approve.add_argument("approval_id")

    p_deny = sub.add_parser("deny")
    p_deny.add_argument("approval_id")
    p_deny.add_argument("--reason", default=None)

    args = parser.parse_args()
    principal = resolve_local_principal()

    store = ApprovalStore(DB_PATH)
    await store.open()
    try:
        if args.cmd == "list":
            await _list(store, principal.user_id if args.mine else None)
        elif args.cmd == "show":
            await _show(store, args.approval_id)
        elif args.cmd == "approve":
            await _approve(store, args.approval_id, principal.user_id)
        elif args.cmd == "deny":
            await _deny(store, args.approval_id, principal.user_id, args.reason)
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(_main())
