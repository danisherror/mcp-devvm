import json
from pathlib import Path

import pytest

from server.approvals.store import ApprovalStore
from server.execution.executor import Executor
from server.proposals.engine import CANONICAL_SCHEMA_VERSION, recompute_proposal_hash
from common.canonical import proposal_hash


class _Audit:
    def __init__(self):
        self.events: list[str] = []

    async def emit(self, event: str, **_fields):
        self.events.append(event)


class _Unreachable:
    """Anything past the hash check touching these means the check didn't stop it."""

    def __getattr__(self, name):
        raise AssertionError(f"executor went past the hash check (touched .{name})")


FIELDS = dict(
    principal_id="usr_1", target_id="dev-vm-01", operation_id="git.checkout",
    manifest_version=1, manifest_hash="h1",
    params={"repo": "api", "branch": "main"}, preconditions={"git.head_sha": "abc"},
)


def _hash(**overrides) -> str:
    f = {**FIELDS, **overrides}
    return proposal_hash(
        v=CANONICAL_SCHEMA_VERSION, principal=f["principal_id"], target_id=f["target_id"],
        operation_id=f["operation_id"], manifest_version=f["manifest_version"],
        manifest_hash=f["manifest_hash"], params=f["params"], preconditions=f["preconditions"],
    )


@pytest.fixture
async def store(tmp_path: Path):
    s = ApprovalStore(tmp_path / "approvals.db")
    await s.open()
    yield s
    await s.close()


async def _approved(store: ApprovalStore):
    h = _hash()
    approval = await store.create(
        request_id="req_1", risk_class="MUTATING_LOCAL", effect_summary={}, reason="test",
        proposal_hash=h, approvals_required=1, ttl_seconds=600, **FIELDS,
    )
    await store.record_decision(approval_id=approval.id, decided_by="usr_lead", decision="APPROVE",
                                displayed_hash=h, channel="test")
    return approval


def _executor(store: ApprovalStore, audit: _Audit) -> Executor:
    x = _Unreachable()
    return Executor(store=store, targets=x, policy=x, registry=x, tunnel=x, tokens=x,
                    audit=audit, reconciler_enqueue=x)


@pytest.mark.asyncio
async def test_recompute_matches_hash_from_proposal(store):
    approval = await _approved(store)
    assert recompute_proposal_hash(await store.get(approval.id)) == _hash()


@pytest.mark.asyncio
@pytest.mark.parametrize("column,value", [
    ("params", {"repo": "api", "branch": "evil"}),
    ("preconditions", {"git.head_sha": "def"}),
    ("params", {"repo": "api", "branch": 1.5}),  # non-canonical value
])
async def test_edit_after_approval_is_unauthorized(store, column, value):
    approval = await _approved(store)
    await store.db.execute(f"UPDATE approvals SET {column}=? WHERE id=?", (json.dumps(value), approval.id))
    await store.db.commit()

    audit = _Audit()
    outcome = await _executor(store, audit).execute(approval.id)

    assert outcome == "UNAUTHORIZED"
    assert "SECURITY_HASH_MISMATCH" in audit.events
    assert (await store.get(approval.id)).error_code == "hash_mismatch"


@pytest.mark.asyncio
async def test_rewriting_both_hash_columns_still_caught(store):
    approval = await _approved(store)
    forged = _hash(params={"repo": "api", "branch": "evil"})
    # Attacker edits params AND rewrites both hash columns to a consistent-looking value,
    # but for different params than what's stored.
    await store.db.execute("UPDATE approvals SET proposal_hash=?, approved_hash=? WHERE id=?",
                           (forged, forged, approval.id))
    await store.db.commit()

    outcome = await _executor(store, _Audit()).execute(approval.id)
    assert outcome == "UNAUTHORIZED"
