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
    """One `user_id<TAB>timestamp` line per user, so one person's step-up
    never counts for (or erases) another's."""

    def __init__(self, path: Path = DEFAULT_STATE_PATH):
        self._path = path

    def _read(self) -> dict[str, float]:
        if not self._path.exists():
            return {}
        entries: dict[str, float] = {}
        for line in self._path.read_text().splitlines():
            uid, sep, ts = line.rpartition("\t")
            if not sep:
                continue  # also skips the old single-user "uid:ts" format
            try:
                entries[uid] = float(ts)
            except ValueError:
                continue
        return entries

    def record(self, user_id: str) -> None:
        entries = self._read()
        entries[user_id] = time.time()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text("".join(f"{uid}\t{ts}\n" for uid, ts in sorted(entries.items())))

    def last_auth_time(self, user_id: str) -> float:
        return self._read().get(user_id, 0.0)


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
