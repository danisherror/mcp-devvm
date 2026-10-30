"""The approval/run state machine (doc §8), with every illegal transition
rejected -- tests/unit/test_state_machine.py asserts each one."""

from __future__ import annotations

TERMINAL_STATES = frozenset(
    {
        "SUCCEEDED", "OP_FAILED", "TIMED_OUT", "STALE", "UNAUTHORIZED", "UNREACHABLE",
        "NEEDS_HUMAN", "DENIED", "EXPIRED", "CANCELLED", "DENIED_BY_POLICY",
    }
)

LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"DENIED", "EXPIRED", "CANCELLED", "APPROVED"}),
    "APPROVED": frozenset({"EXPIRED", "CLAIMED"}),
    "CLAIMED": frozenset({"STALE", "UNAUTHORIZED", "UNREACHABLE", "RUNNING"}),
    # STALE / UNAUTHORIZED from RUNNING: devd itself refused before starting
    # the effect (409 precondition drift, 403 missing approval signature).
    "RUNNING": frozenset({"SUCCEEDED", "OP_FAILED", "TIMED_OUT", "UNKNOWN", "STALE", "UNAUTHORIZED"}),
    "UNKNOWN": frozenset({"SUCCEEDED", "OP_FAILED", "TIMED_OUT", "NEEDS_HUMAN"}),
}

ALL_STATES = frozenset(LEGAL_TRANSITIONS) | TERMINAL_STATES


class IllegalTransition(Exception):
    pass


def validate_transition(current: str, new: str) -> None:
    if current in TERMINAL_STATES:
        raise IllegalTransition(f"{current} is terminal; cannot move to {new}")
    allowed = LEGAL_TRANSITIONS.get(current, frozenset())
    if new not in allowed:
        raise IllegalTransition(f"{current} -> {new} is not a legal transition")
