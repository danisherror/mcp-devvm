"""The authorization matrix: user x target x operation x risk (doc §10.1).

`PRIVILEGE` is intentionally ungrantable through this server, regardless of
what any policy file says -- enforced in code, not just by convention.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from common.manifest import OperationManifest
from server.auth.principal import Principal


@dataclass(frozen=True)
class PolicyRule:
    roles: tuple[str, ...]
    targets: tuple[str, ...]
    operation_globs: tuple[str, ...]
    risks: tuple[str, ...]
    require_step_up: tuple[str, ...]
    require_four_eyes: tuple[str, ...]
    max_runs_per_hour: int


class PolicyMatrix:
    def __init__(self, rules: list[PolicyRule]):
        self._rules = rules

    def _matching_rules(self, principal: Principal, target_id: str) -> Iterator[PolicyRule]:
        principal_roles = set(principal.roles)
        for rule in self._rules:
            if not (principal_roles & set(rule.roles)):
                continue
            if target_id not in rule.targets:
                continue
            yield rule

    def can_see_target(self, principal: Principal, target_id: str) -> bool:
        """A target is visible to a principal only if some rule grants them
        something on it; others look exactly like targets that don't exist."""
        return any(True for _ in self._matching_rules(principal, target_id))

    def allows(self, principal: Principal, target_id: str, op: OperationManifest) -> bool:
        if op.risk == "PRIVILEGE":
            return False  # ungrantable, no exceptions (§10.1)
        for rule in self._matching_rules(principal, target_id):
            if op.risk not in rule.risks:
                continue
            if any(fnmatch.fnmatch(op.id, glob) for glob in rule.operation_globs):
                return True
        return False

    def requires_step_up(self, principal: Principal, target_id: str, op: OperationManifest) -> bool:
        return any(op.risk in rule.require_step_up for rule in self._matching_rules(principal, target_id))

    def requires_four_eyes(self, principal: Principal, target_id: str, op: OperationManifest) -> bool:
        return any(op.risk in rule.require_four_eyes for rule in self._matching_rules(principal, target_id))

    def max_runs_per_hour(self, principal: Principal, target_id: str) -> int:
        limits = [rule.max_runs_per_hour for rule in self._matching_rules(principal, target_id)]
        return max(limits) if limits else 0


def load_policy(path: Path) -> PolicyMatrix:
    raw = yaml.safe_load(path.read_text()) or {}
    rules = [
        PolicyRule(
            roles=tuple(r["roles"]),
            targets=tuple(r["targets"]),
            operation_globs=tuple(r.get("operations", ["*"])),
            risks=tuple(r["risks"]),
            require_step_up=tuple(r.get("require_step_up", [])),
            require_four_eyes=tuple(r.get("require_four_eyes", [])),
            max_runs_per_hour=r.get("max_runs_per_hour", 60),
        )
        for r in raw.get("policies", [])
    ]
    return PolicyMatrix(rules)
