"""The cross-plane correlation report (scripts/correlate.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.correlate import approval_free_operations, correlate, load_approvals, load_runs
from server.approvals.store import ApprovalStore

T0 = 1_700_000_000.0
FREE = {"git.status", "logs.tail"}


def _run(run_id="run_1", approval_id="appr_1", **kw):
    d = {"run_id": run_id, "approval_id": approval_id, "operation_id": "git.checkout",
         "principal": "os:alice", "started_at": T0 + 10, "idempotency_key": approval_id}
    d.update(kw)
    return d


def _approval(id="appr_1", **kw):
    d = {"id": id, "principal_id": "os:alice", "target_id": "dev-vm-01", "operation_id": "git.checkout",
         "status": "SUCCEEDED", "decided_at": T0, "approved_expires_at": T0 + 120, "run_id": "run_1"}
    d.update(kw)
    return d


def _check(runs, approvals):
    return correlate(runs, {a["id"]: a for a in approvals}, target_id="dev-vm-01", approval_free_ops=FREE)


def test_matching_run_is_clean():
    assert _check([_run()], [_approval()]) == []


def test_direct_read_of_a_read_only_op_is_clean():
    assert _check([_run(approval_id="n/a:direct-read", operation_id="git.status")], []) == []


@pytest.mark.parametrize("run,approval,problem", [
    (_run(approval_id="appr_ghost"), None, "no matching approval"),
    (_run(approval_id="n/a:direct-read"), None, "requires approval"),
    (_run(approval_id="n/a:preconditions"), None, "non-run token"),
    (_run(operation_id="service.restart"), _approval(), "approval is for git.checkout"),
    (_run(principal="os:mallory"), _approval(), "requested by os:alice"),
    (_run(), _approval(target_id="dev-vm-02"), "approval is for dev-vm-02"),
    (_run(), _approval(status="DENIED"), "never allows a run"),
    (_run(), _approval(status="PENDING", decided_at=None, approved_expires_at=None, run_id=None),
     "never allows a run"),
    (_run(started_at=T0 - 600), _approval(), "before the approval was decided"),
    (_run(started_at=T0 + 600), _approval(), "execution window closed"),
    (_run(run_id="run_2"), _approval(), "recorded run run_1"),
])
def test_bypasses_are_flagged(run, approval, problem):
    findings = _check([run], [approval] if approval else [])
    assert any(f.severity == "bypass" and problem in f.problem for f in findings), findings


def test_two_runs_for_one_approval_are_flagged():
    findings = _check([_run(), _run(run_id="run_2")], [_approval(run_id=None)])
    assert any("2 runs for one approval" in f.problem for f in findings)


def test_server_run_missing_on_devd_is_a_check():
    findings = _check([], [_approval()])
    assert [f.severity for f in findings] == ["check"]


def test_other_targets_approvals_are_ignored():
    assert _check([], [_approval(target_id="dev-vm-02")]) == []


def test_free_operations_come_from_the_manifests():
    ops = Path(__file__).resolve().parents[2] / "devd" / "operations"
    assert approval_free_operations(ops) == {"git.status", "logs.tail"}


def test_runs_dir_and_real_store_are_read(tmp_path):
    import asyncio

    run_dir = tmp_path / "runs" / "run_1"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({k: v for k, v in _run().items() if k != "run_id"}))
    (tmp_path / "runs" / "run_bad").mkdir()
    (tmp_path / "runs" / "run_bad" / "meta.json").write_text("{not json")

    async def make_db():
        store = ApprovalStore(tmp_path / "approvals.db")
        await store.open()
        a = await store.create(
            principal_id="os:alice", request_id="r", target_id="dev-vm-01", operation_id="git.checkout",
            manifest_version=1, manifest_hash="h", params={}, preconditions={}, risk_class="MUTATING_LOCAL",
            effect_summary={}, reason="t", proposal_hash="p", approvals_required=1, ttl_seconds=600,
        )
        await store.close()
        return a.id

    approval_id = asyncio.run(make_db())
    approvals = load_approvals(tmp_path / "approvals.db")
    assert approvals[approval_id]["status"] == "PENDING"
    runs = load_runs(tmp_path / "runs")
    assert {r["run_id"] for r in runs} == {"run_1", "run_bad"}
    findings = correlate(runs, approvals, target_id="dev-vm-01", approval_free_ops=FREE)
    assert any(f.run_id == "run_bad" and "missing fields" in f.problem for f in findings)
