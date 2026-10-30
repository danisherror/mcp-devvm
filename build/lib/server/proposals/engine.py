"""Builds the canonical proposal + its hash (doc §7.4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.canonical import NonCanonicalValue, proposal_hash
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


def recompute_proposal_hash(approval: Any) -> str | None:
    """Re-derive the proposal hash from an approval's stored fields.

    Callers compare this against the stored hashes instead of trusting them,
    so editing params/preconditions in the DB after proposal is detected.
    Returns None if the stored fields can't be canonicalized at all (e.g. a
    float was written into params), which callers treat as a mismatch.
    """
    try:
        return proposal_hash(
            v=CANONICAL_SCHEMA_VERSION,
            principal=approval.principal_id,
            target_id=approval.target_id,
            operation_id=approval.operation_id,
            manifest_version=approval.manifest_version,
            manifest_hash=approval.manifest_hash,
            params=approval.params,
            preconditions=approval.preconditions,
        )
    except NonCanonicalValue:
        return None
