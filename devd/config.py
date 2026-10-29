"""devd's own local configuration -- workspace roots, service state paths,
socket path, keys. Loaded once at startup from the local filesystem; never
supplied by a request (B5)."""

from __future__ import annotations

import os
from pathlib import Path

DEVD_HOME = Path(os.environ.get("DEVD_HOME", "/var/lib/devd"))
OPERATIONS_DIR = Path(os.environ.get("DEVD_OPERATIONS_DIR", "/opt/devd/operations"))
RUNS_DIR = DEVD_HOME / "runs"
SOCKET_PATH = Path(os.environ.get("DEVD_SOCKET", "/run/devd/devd.sock"))
TOKEN_PUBLIC_KEY_PATH = Path(os.environ.get("DEVD_TOKEN_PUBKEY", "/etc/devd/token_signing_key.pub"))
# Human approvers' public keys, one <name>.pub per approver (common/approval_sig.py).
APPROVERS_DIR = Path(os.environ.get("DEVD_APPROVERS_DIR", "/etc/devd/approvers"))
AUDIENCE_PREFIX = "devd:"
TARGET_ID = os.environ.get("DEVD_TARGET_ID", "dev-vm-01")

WORKSPACES: dict[str, Path] = {
    "api": Path(os.environ.get("DEVD_WORKSPACE_API", "/srv/workspace/api")),
    "web": Path(os.environ.get("DEVD_WORKSPACE_WEB", "/srv/workspace/web")),
}

SERVICE_STATE_DIR = Path(os.environ.get("DEVD_SERVICE_STATE_DIR", "/srv/services"))
LOG_DIR = Path(os.environ.get("DEVD_LOG_DIR", "/srv/logs"))

MAX_CONCURRENT_RUNS = int(os.environ.get("DEVD_MAX_CONCURRENT_RUNS", "3"))
