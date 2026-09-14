"""Builds the canonical proposal + its hash (doc §7.4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.canonical import proposal_hash
from common.manifest import OperationManifest
from server.auth.principal import Principal
from server.policy.targets import Target

CANONICAL_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Proposal:
    principal_id: str
    target_id: str
    operation_id: str
    manifest_version: int
    manifest_hash: str
    params: dict[str, Any]
    preconditions: dict[str, Any]
    risk: str
    effect: dict[str, Any]
    hash: str


def build_proposal(
    *, principal: Principal, target: Target, op: OperationManifest, params: dict[str, Any], preconditions: dict[str, Any]
) -> Proposal:
    h = proposal_hash(
        v=CANONICAL_SCHEMA_VERSION,
        principal=principal.user_id,
        target_id=target.id,
        operation_id=op.id,
        manifest_version=op.version,
        manifest_hash=op.content_hash,
        params=params,
        preconditions=preconditions,
    )
    return Proposal(
        principal_id=principal.user_id,
        target_id=target.id,
        operation_id=op.id,
        manifest_version=op.version,
        manifest_hash=op.content_hash,
        params=params,
        preconditions=preconditions,
        risk=op.risk,
        effect=op.effect.render(params),
        hash=h,
    )
