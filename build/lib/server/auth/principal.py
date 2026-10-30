"""Principal: identity derived exclusively from a verified session, never
from a tool argument (doc §1.1 invariant 3, §9.1).

Local topology (this template): the OS session identifies the user. That is
identification, not authentication (§3.1) -- there is no cryptographic proof
an attacker with code execution as this OS user couldn't also produce. We
still build the full Principal object and thread it everywhere, because that
is the entire migration path to the remote/OIDC topology later: nothing
downstream of this module would need to change.

Step-up freshness is deliberately NOT a field on Principal: this object is
re-resolved on every request (there is no session to expire), so an
`auth_time` set at resolution time would always read as "just authenticated"
and the step-up check would be vacuous. Step-up freshness instead comes from
`server.auth.step_up.StepUpStore`, a separately recorded, deliberate re-auth
event -- see that module.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    user_id: str
    display_name: str
    roles: tuple[str, ...]


def resolve_local_principal(roles: tuple[str, ...] = ("developer",)) -> Principal:
    user = getpass.getuser() or os.environ.get("USER", "unknown")
    return Principal(user_id=f"os:{user}", display_name=user, roles=roles)
