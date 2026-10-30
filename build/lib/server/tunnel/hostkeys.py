"""Host key pinning (doc §11.2, §12.3). A mismatch is an alert, never a
prompt -- never `known_hosts=None`, never AutoAddPolicy."""

from __future__ import annotations

from pathlib import Path

from server.policy.targets import Target


def known_hosts_path(target: Target, *, pin_dir: Path) -> Path:
    pin_dir.mkdir(parents=True, exist_ok=True)
    path = pin_dir / f"{target.id}.known_hosts"
    line = f"{target.ssh_host} {target.host_key}\n"
    if not path.exists() or path.read_text() != line:
        path.write_text(line)
    return path
