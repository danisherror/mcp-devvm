"""devd/config.py reads its paths from the environment at import time, and
defaults to production paths (/var/lib/devd, /opt/devd/operations, ...) that
don't exist and aren't writable outside the real container. Point them at a
throwaway directory before anything in the test session imports devd.*.
"""

import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="devd-test-"))
os.environ.setdefault("DEVD_HOME", str(_tmp / "home"))
os.environ.setdefault("DEVD_OPERATIONS_DIR", str(Path(__file__).resolve().parent.parent / "devd" / "operations"))
os.environ.setdefault("DEVD_SOCKET", str(_tmp / "devd.sock"))
os.environ.setdefault("DEVD_TOKEN_PUBKEY", str(_tmp / "token_signing_key.pub"))
os.environ.setdefault("DEVD_TARGET_ID", "dev-vm-01")
os.environ.setdefault("DEVD_WORKSPACE_API", str(_tmp / "workspace" / "api"))
os.environ.setdefault("DEVD_WORKSPACE_WEB", str(_tmp / "workspace" / "web"))
os.environ.setdefault("DEVD_SERVICE_STATE_DIR", str(_tmp / "services"))
os.environ.setdefault("DEVD_LOG_DIR", str(_tmp / "logs"))
