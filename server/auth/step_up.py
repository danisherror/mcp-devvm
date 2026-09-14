"""Step-up re-authentication, local-topology stand-in (doc §9.1).

In the remote/OIDC topology, step-up means "re-run the OIDC flow and check
`auth_time`." Locally there is no IdP to re-challenge, so this offers the
same *shape* of control -- a recorded, timestamped re-auth event a policy
check can require to be recent -- via a CLI command
(`python -m server.auth.step_up reauth`) that asks for the OS password via
`getpass` and simply re-confirms the OS session. It is honest about being
identification, not cryptographic re-authentication (§3.1).
"""

from __future__ import annotations

import time
from pathlib import Path

DEFAULT_STATE_PATH = Path("data/step_up.state")


class StepUpStore:
    def __init__(self, path: Path = DEFAULT_STATE_PATH):
        self._path = path

    def record(self, user_id: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(f"{user_id}:{time.time()}")

    def last_auth_time(self, user_id: str) -> float:
        if not self._path.exists():
            return 0.0
        try:
            uid, ts = self._path.read_text().strip().split(":", 1)
        except ValueError:
            return 0.0
        return float(ts) if uid == user_id else 0.0


if __name__ == "__main__":
    import getpass
    import sys

    from server.auth.principal import resolve_local_principal

    if len(sys.argv) != 2 or sys.argv[1] != "reauth":
        print("usage: python -m server.auth.step_up reauth")
        raise SystemExit(2)

    principal = resolve_local_principal()
    getpass.getpass(f"Re-confirm it's you ({principal.display_name}), press enter: ")
    StepUpStore().record(principal.user_id)
    print(f"step-up recorded for {principal.user_id}")
