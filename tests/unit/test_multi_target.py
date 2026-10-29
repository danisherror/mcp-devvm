"""Several targets and several users: resolution, visibility, step-up."""

from __future__ import annotations

import pytest

from server.auth.principal import Principal
from server.auth.step_up import StepUpStore
from server.policy.matrix import PolicyMatrix, PolicyRule
from server.policy.targets import Target
from server.services.operation_service import OperationService, ToolError


def _target(tid: str) -> Target:
    return Target(id=tid, label=f"label-{tid}", ssh_host="127.0.0.1", ssh_port=22, ssh_user="devd-tunnel",
                  host_key="ssh-ed25519 AAAA", local_socket_path=f"/tmp/{tid}.sock", max_concurrent_runs=1)


def _rule(roles, targets):
    return PolicyRule(roles=tuple(roles), targets=tuple(targets), operation_globs=("*",), risks=("READ_ONLY",),
                      require_step_up=(), require_four_eyes=(), max_runs_per_hour=10)


@pytest.fixture
def service():
    policy = PolicyMatrix([_rule(["developer"], ["vm-a"]), _rule(["tech-lead"], ["vm-a", "vm-b"])])
    targets = {"vm-a": _target("vm-a"), "vm-b": _target("vm-b")}
    return OperationService(store=None, targets=targets, policy=policy, registry=None, tunnel=None, tokens=None,
                            audit=None, executor=None, reconciler=None, step_up=None)


DEV = Principal(user_id="os:dev", display_name="dev", roles=("developer",))
LEAD = Principal(user_id="os:lead", display_name="lead", roles=("tech-lead",))
NOBODY = Principal(user_id="os:x", display_name="x", roles=("intern",))


async def test_users_only_see_targets_their_policy_grants(service):
    assert [t["target_id"] for t in await service.list_targets(DEV)] == ["vm-a"]
    assert [t["target_id"] for t in await service.list_targets(LEAD)] == ["vm-a", "vm-b"]
    assert await service.list_targets(NOBODY) == []


async def test_single_visible_target_is_the_default(service):
    assert (await service.describe_target(DEV))["target_id"] == "vm-a"


async def test_several_visible_targets_require_an_explicit_id(service):
    with pytest.raises(ToolError, match="target_required"):
        await service.describe_target(LEAD)
    assert (await service.describe_target(LEAD, "vm-b"))["label"] == "label-vm-b"


async def test_hidden_target_looks_like_a_missing_one(service):
    with pytest.raises(ToolError, match="^unknown_target$"):
        await service.describe_target(DEV, "vm-b")
    with pytest.raises(ToolError, match="^unknown_target$"):
        await service.describe_target(DEV, "does-not-exist")


def test_step_up_is_tracked_per_user(tmp_path):
    store = StepUpStore(tmp_path / "step_up.state")
    store.record("os:alice")
    store.record("os:bob")
    assert store.last_auth_time("os:alice") > 0
    assert store.last_auth_time("os:bob") > 0
    assert store.last_auth_time("os:carol") == 0.0


def test_old_single_user_step_up_file_is_ignored(tmp_path):
    path = tmp_path / "step_up.state"
    path.write_text("os:alice:1700000000.0")
    assert StepUpStore(path).last_auth_time("os:alice") == 0.0
