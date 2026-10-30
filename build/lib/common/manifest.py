"""The operation manifest shape (doc §5.1, §5.6), shared by both planes.

devd loads manifests directly from local YAML files on disk. The control
plane obtains the *same shape* as JSON over `GET /manifest` through the
tunnel. Sharing this dataclass module does not make the two trust each
other's copy -- each side independently computes/receives its own
`content_hash` and devd is the one that ultimately re-validates params and
rejects a version/hash mismatch (§12.1, B5).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from common.canonical import content_hash
from common.paramschema import Param

RISK_CLASSES = (
    "READ_ONLY",
    "MUTATING_LOCAL",
    "SERVICE_CONTROL",
    "NETWORK_EXEC",
    "DESTRUCTIVE",
    "PRIVILEGE",
)


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class EffectDeclaration:
    description: str
    writes: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    network: tuple[str, ...] = ()
    services: tuple[str, ...] = ()

    def render(self, params: dict[str, Any]) -> dict[str, Any]:
        def fmt(s: str) -> str:
            try:
                return s.format(**params)
            except (KeyError, IndexError):
                return s

        return {
            "description": fmt(self.description),
            "writes": [fmt(p) for p in self.writes],
            "reads": [fmt(p) for p in self.reads],
            "network": list(self.network),
            "services": list(self.services),
        }


@dataclass(frozen=True)
class ReversibleHint:
    kind: str
    restore_hint: str


@dataclass(frozen=True)
class SandboxSpec:
    mode: str  # "none" | "namespace"
    timeout_s: int
    max_output_bytes: int


@dataclass(frozen=True)
class OperationManifest:
    id: str
    version: int
    summary: str
    params: dict[str, Param]
    effect: EffectDeclaration
    risk: str
    approval_required: bool
    preconditions: tuple[str, ...]
    reversible: ReversibleHint | None
    sandbox: SandboxSpec
    content_hash: str = ""  # filled in by the loader

    def as_dict(self) -> dict[str, Any]:
        """JSON-serializable form served by devd's /manifest and consumed by the
        control plane's registry client -- the wire shape both sides agree on."""
        return {
            "id": self.id,
            "version": self.version,
            "summary": self.summary,
            "params": {
                name: {
                    "type": p.type,
                    "pattern": p.pattern,
                    "max_length": p.max_length,
                    "allow_leading_dash": p.allow_leading_dash,
                    "values": list(p.values),
                    "min_value": p.min_value,
                    "max_value": p.max_value,
                }
                for name, p in self.params.items()
            },
            "effect": {
                "description": self.effect.description,
                "writes": list(self.effect.writes),
                "reads": list(self.effect.reads),
                "network": list(self.effect.network),
                "services": list(self.effect.services),
            },
            "risk": self.risk,
            "approval_required": self.approval_required,
            "preconditions": list(self.preconditions),
            "reversible": (
                {"kind": self.reversible.kind, "restore_hint": self.reversible.restore_hint}
                if self.reversible
                else None
            ),
            "sandbox": {
                "mode": self.sandbox.mode,
                "timeout_s": self.sandbox.timeout_s,
                "max_output_bytes": self.sandbox.max_output_bytes,
            },
            "content_hash": self.content_hash,
        }


def _param_from_dict(name: str, d: dict[str, Any]) -> Param:
    try:
        return Param(
            type=d["type"],
            pattern=d.get("pattern"),
            max_length=d.get("max_length", 200),
            allow_leading_dash=d.get("allow_leading_dash", False),
            values=tuple(d.get("values", ())),
            min_value=d.get("min_value"),
            max_value=d.get("max_value"),
        )
    except (KeyError, ValueError) as exc:
        raise ManifestError(f"param {name!r}: {exc}") from exc


def manifest_from_yaml_dict(raw: dict[str, Any], *, impl_source: bytes) -> OperationManifest:
    """Used by devd: parse a manifest YAML file plus the bytes of its
    implementation module, and compute the operation's content_hash from
    both -- so a behavioural change to either bumps the hash (§5.6)."""
    try:
        op_id = raw["id"]
        version = int(raw["version"])
        summary = raw["summary"]
        params = {name: _param_from_dict(name, d) for name, d in raw.get("params", {}).items()}
        effect_raw = raw["effect"]
        effect = EffectDeclaration(
            description=effect_raw["description"].strip(),
            writes=tuple(effect_raw.get("writes", ())),
            reads=tuple(effect_raw.get("reads", ())),
            network=tuple(effect_raw.get("network", ())),
            services=tuple(effect_raw.get("services", ())),
        )
        risk = raw["risk"]
        if risk not in RISK_CLASSES:
            raise ManifestError(f"unknown risk class {risk!r}")
        approval_required = raw.get("approval", "required") == "required"
        preconditions = tuple(raw.get("preconditions", ()))
        reversible_raw = raw.get("reversible")
        reversible = (
            ReversibleHint(kind=reversible_raw["kind"], restore_hint=reversible_raw["restore_hint"])
            if reversible_raw
            else None
        )
        sandbox_raw = raw["sandbox"]
        sandbox = SandboxSpec(
            mode=sandbox_raw.get("mode", "namespace"),
            timeout_s=int(sandbox_raw["timeout_s"]),
            max_output_bytes=int(sandbox_raw.get("max_output_bytes", 262_144)),
        )
    except KeyError as exc:
        raise ManifestError(f"missing required field: {exc}") from exc

    manifest_content = {
        "id": op_id,
        "version": version,
        "summary": summary,
        "params": {n: p.__dict__ for n, p in params.items()},
        "effect": effect.__dict__,
        "risk": risk,
        "approval_required": approval_required,
        "preconditions": list(preconditions),
        "sandbox": sandbox.__dict__,
    }
    op_hash = hashlib.sha256(
        content_hash(manifest_content).encode() + hashlib.sha256(impl_source).digest()
    ).hexdigest()

    return OperationManifest(
        id=op_id,
        version=version,
        summary=summary,
        params=params,
        effect=effect,
        risk=risk,
        approval_required=approval_required,
        preconditions=preconditions,
        reversible=reversible,
        sandbox=sandbox,
        content_hash=op_hash,
    )


def manifest_from_wire_dict(raw: dict[str, Any]) -> OperationManifest:
    """Used by the control plane: parse the JSON shape served by devd's
    /manifest. `content_hash` is taken as reported -- it is later checked
    against what devd re-computes locally, never trusted on its own (B5)."""
    params = {name: _param_from_dict(name, d) for name, d in raw["params"].items()}
    effect_raw = raw["effect"]
    effect = EffectDeclaration(
        description=effect_raw["description"],
        writes=tuple(effect_raw.get("writes", ())),
        reads=tuple(effect_raw.get("reads", ())),
        network=tuple(effect_raw.get("network", ())),
        services=tuple(effect_raw.get("services", ())),
    )
    reversible_raw = raw.get("reversible")
    reversible = (
        ReversibleHint(kind=reversible_raw["kind"], restore_hint=reversible_raw["restore_hint"])
        if reversible_raw
        else None
    )
    sandbox_raw = raw["sandbox"]
    sandbox = SandboxSpec(
        mode=sandbox_raw["mode"],
        timeout_s=sandbox_raw["timeout_s"],
        max_output_bytes=sandbox_raw["max_output_bytes"],
    )
    return OperationManifest(
        id=raw["id"],
        version=raw["version"],
        summary=raw["summary"],
        params=params,
        effect=effect,
        risk=raw["risk"],
        approval_required=raw["approval_required"],
        preconditions=tuple(raw.get("preconditions", ())),
        reversible=reversible,
        sandbox=sandbox,
        content_hash=raw["content_hash"],
    )
