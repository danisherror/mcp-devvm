"""Local-topology role assignment: user_id -> roles, loaded from a small
config file rather than hardcoded, so both the MCP tool layer and the
executor's re-derivation-at-execution-time (doc §10.2 step 10: "repeat
1-7 against fresh state") agree on the same source of truth."""

from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_ROLES: tuple[str, ...] = ("developer",)


def load_role_map(path: Path) -> dict[str, tuple[str, ...]]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    return {user_id: tuple(roles) for user_id, roles in raw.get("users", {}).items()}


def resolve_roles(user_id: str, role_map: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    return role_map.get(user_id, DEFAULT_ROLES)
