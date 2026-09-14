"""Target config: server-side only, never reachable from the agent (doc
§9.2). The agent learns a `label` and nothing routable."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Target:
    id: str
    label: str
    ssh_host: str
    ssh_port: int
    ssh_user: str
    host_key: str
    local_socket_path: str
    remote_socket_path: str
    max_concurrent_runs: int


def load_targets(path: Path) -> dict[str, Target]:
    raw = yaml.safe_load(path.read_text()) or {}
    targets: dict[str, Target] = {}
    for target_id, t in raw.get("targets", {}).items():
        targets[target_id] = Target(
            id=target_id,
            label=t["label"],
            ssh_host=t["ssh_host"],
            ssh_port=t.get("ssh_port", 22),
            ssh_user=t["ssh_user"],
            host_key=t["host_key"],
            local_socket_path=t["local_socket_path"],
            remote_socket_path=t["remote_socket_path"],
            max_concurrent_runs=t.get("max_concurrent_runs", 3),
        )
    return targets
