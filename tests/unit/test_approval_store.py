import asyncio
from pathlib import Path

import pytest

from server.approvals.state_machine import IllegalTransition
from server.approvals.store import ApprovalStore


@pytest.fixture
async def store(tmp_path: Path):
    s = ApprovalStore(tmp_path / "approvals.db")
    await s.open()
    yield s
    await s.close()


async def _make_pending(store: ApprovalStore, **overrides):
    defaults = dict(
        principal_id="usr_1", request_id="req_1", target_id="dev-vm-01", operation_id="git.checkout",
        manifest_version=1, manifest_hash="h1", params={"repo": "api", "branch": "main"},
        preconditions={"git.head_sha": "abc"}, risk_class="MUTATING_LOCAL",
        effect_summary={"writes": ["/srv/workspace/api"]}, reason="test", proposal_hash="ph1",
        approvals_required=1, ttl_seconds=600,
    )
    defaults.update(overrides)
    return await store.create(**defaults)


@pytest.mark.asyncio
async def test_create_and_get(store):
    approval = await _make_pending(store)
    assert approval.status == "PENDING"
    fetched = await store.get(approval.id)
    assert fetched.id == approval.id
    assert fetched.params == {"repo": "api", "branch": "main"}


@pytest.mark.asyncio
async def test_approve_then_claim_then_settle(store):
    approval = await _make_pending(store)
    approved = await store.record_decision(
        approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
        displayed_hash="ph1", channel="cli",
    )
    assert approved.status == "APPROVED"

    claimed = await store.claim(approval.id, worker_id="worker-1")
    assert claimed is not None
    assert claimed.status == "CLAIMED"

    await store.set_status(approval.id, "RUNNING")
    await store.settle(approval.id, "SUCCEEDED", run_id="run_1")

    final = await store.get(approval.id)
    assert final.status == "SUCCEEDED"
    assert final.run_id == "run_1"


@pytest.mark.asyncio
async def test_deny_terminates(store):
    approval = await _make_pending(store)
    result = await store.record_decision(
        approval_id=approval.id, decided_by="usr_lead", decision="DENY",
        displayed_hash="ph1", channel="cli",
    )
    assert result.status == "DENIED"
    # claim() never raises on a bad source state -- it CAS-guards on
    # status='APPROVED' and simply no-ops (returns None) otherwise (§10.2).
    claimed = await store.claim(approval.id, worker_id="worker-1")
    assert claimed is None


@pytest.mark.asyncio
async def test_execute_without_approval_record_rejected(store):
    # Claiming a nonexistent / never-approved approval is simply a no-op (§25.4).
    result = await store.claim("appr_does_not_exist", worker_id="worker-1")
    assert result is None


@pytest.mark.asyncio
async def test_claim_loses_on_already_settled_approval(store):
    approval = await _make_pending(store)
    await store.record_decision(approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
                                 displayed_hash="ph1", channel="cli")
    first = await store.claim(approval.id, worker_id="worker-1")
    assert first is not None
    # A second claim on the same (now CLAIMED, not APPROVED) approval must lose.
    second = await store.claim(approval.id, worker_id="worker-2")
    assert second is None


@pytest.mark.asyncio
async def test_two_workers_race_to_claim_exactly_one_wins(store):
    approval = await _make_pending(store)
    await store.record_decision(approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
                                 displayed_hash="ph1", channel="cli")

    results = await asyncio.gather(
        *(store.claim(approval.id, worker_id=f"worker-{i}") for i in range(10))
    )
    winners = [r for r in results if r is not None]
    assert len(winners) == 1


@pytest.mark.asyncio
async def test_four_eyes_same_human_approving_twice_counts_once(store):
    approval = await _make_pending(store, approvals_required=2)
    r1 = await store.record_decision(approval_id=approval.id, decided_by="usr_a", decision="APPROVE",
                                      displayed_hash="ph1", channel="cli")
    assert r1.status == "PENDING"  # only one distinct approver so far
    r2 = await store.record_decision(approval_id=approval.id, decided_by="usr_a", decision="APPROVE",
                                      displayed_hash="ph1", channel="cli")
    assert r2.status == "PENDING"  # same human again -- still counts once
    r3 = await store.record_decision(approval_id=approval.id, decided_by="usr_b", decision="APPROVE",
                                      displayed_hash="ph1", channel="cli")
    assert r3.status == "APPROVED"  # second DISTINCT approver crosses the threshold


@pytest.mark.asyncio
async def test_requester_cannot_approve_own_four_eyes_request(store):
    approval = await _make_pending(store, principal_id="os:alice", approvals_required=2)
    with pytest.raises(IllegalTransition, match="requester"):
        await store.record_decision(approval_id=approval.id, decided_by="os:alice", decision="APPROVE",
                                     displayed_hash="ph1", channel="cli")
    # DESTRUCTIVE is four-eyes even if the row says 1, matching devd.
    destructive = await _make_pending(store, request_id="req_2", principal_id="os:alice", risk_class="DESTRUCTIVE")
    with pytest.raises(IllegalTransition, match="requester"):
        await store.record_decision(approval_id=destructive.id, decided_by="os:alice", decision="APPROVE",
                                     displayed_hash="ph1", channel="cli")


@pytest.mark.asyncio
async def test_requester_may_approve_single_approval(store):
    approval = await _make_pending(store, principal_id="os:alice")
    result = await store.record_decision(approval_id=approval.id, decided_by="os:alice", decision="APPROVE",
                                          displayed_hash="ph1", channel="cli")
    assert result.status == "APPROVED"


@pytest.mark.asyncio
async def test_expired_decision_window_rejects_decision(store):
    approval = await _make_pending(store, ttl_seconds=-1)  # already expired
    with pytest.raises(IllegalTransition):
        await store.record_decision(approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
                                     displayed_hash="ph1", channel="cli")
    expired = await store.get(approval.id)
    assert expired.status == "EXPIRED"


@pytest.mark.asyncio
async def test_settle_on_already_settled_approval_rejected(store):
    approval = await _make_pending(store)
    await store.record_decision(approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
                                 displayed_hash="ph1", channel="cli")
    await store.claim(approval.id, worker_id="worker-1")
    await store.set_status(approval.id, "RUNNING")
    await store.settle(approval.id, "SUCCEEDED", run_id="run_1")

    with pytest.raises(IllegalTransition):
        await store.settle(approval.id, "SUCCEEDED", run_id="run_2")  # idempotent no-op, not a re-settle


@pytest.mark.asyncio
async def test_destructive_needs_two_approvals_even_if_row_says_one(store):
    # devd always wants two signatures for DESTRUCTIVE; the store must not
    # mark APPROVED with one, whatever approvals_required says.
    approval = await _make_pending(store, risk_class="DESTRUCTIVE", approvals_required=1)
    result = await store.record_decision(
        approval_id=approval.id, decided_by="os:alice", decision="APPROVE", displayed_hash="ph1", channel="cli",
    )
    assert result.status == "PENDING"
    result = await store.record_decision(
        approval_id=approval.id, decided_by="os:bob", decision="APPROVE", displayed_hash="ph1", channel="cli",
    )
    assert result.status == "APPROVED"
