"""The local tunnel socket is private from the moment it exists."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from server.tunnel.manager import bind_private_unix_socket


def test_socket_is_owner_only_and_umask_is_restored():
    # AF_UNIX paths are limited to ~104 bytes on macOS, so use a short dir.
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        path = Path(d) / "t.sock"
        old = os.umask(0o022)
        try:
            sock = bind_private_unix_socket(path)
            try:
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                assert os.umask(0o022) == 0o022  # restored
            finally:
                sock.close()
        finally:
            os.umask(old)
