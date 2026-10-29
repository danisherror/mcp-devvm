import pytest

from server.approvals.state_machine import ALL_STATES, TERMINAL_STATES, IllegalTransition, validate_transition


@pytest.mark.parametrize(
    "current,new",
    [
        ("PENDING", "APPROVED"),
        ("PENDING", "DENIED"),
        ("PENDING", "EXPIRED"),
        ("PENDING", "CANCELLED"),
        ("APPROVED", "CLAIMED"),
        ("APPROVED", "EXPIRED"),
        ("CLAIMED", "RUNNING"),
        ("CLAIMED", "STALE"),
        ("CLAIMED", "UNAUTHORIZED"),
        ("CLAIMED", "UNREACHABLE"),
        ("RUNNING", "SUCCEEDED"),
        ("RUNNING", "OP_FAILED"),
        ("RUNNING", "TIMED_OUT"),
        ("RUNNING", "UNKNOWN"),
        ("RUNNING", "STALE"),
        ("RUNNING", "UNAUTHORIZED"),
        ("UNKNOWN", "SUCCEEDED"),
        ("UNKNOWN", "OP_FAILED"),
        ("UNKNOWN", "TIMED_OUT"),
        ("UNKNOWN", "NEEDS_HUMAN"),
    ],
)
def test_legal_transitions_accepted(current, new):
    validate_transition(current, new)  # must not raise


@pytest.mark.parametrize(
    "current,new",
    [
        ("PENDING", "RUNNING"),  # cannot skip APPROVED -> CLAIMED
        ("PENDING", "CLAIMED"),
        ("APPROVED", "RUNNING"),  # no APPROVED -> RUNNING edge; CLAIMED is mandatory
        ("APPROVED", "SUCCEEDED"),
        ("CLAIMED", "SUCCEEDED"),  # must pass through RUNNING first
        ("CLAIMED", "PENDING"),
        ("RUNNING", "CLAIMED"),
        ("RUNNING", "APPROVED"),
        ("UNKNOWN", "RUNNING"),
        ("UNKNOWN", "CLAIMED"),
    ],
)
def test_illegal_transitions_rejected(current, new):
    with pytest.raises(IllegalTransition):
        validate_transition(current, new)


@pytest.mark.parametrize("terminal", sorted(TERMINAL_STATES))
def test_terminal_states_reject_every_transition(terminal):
    for target in ALL_STATES:
        with pytest.raises(IllegalTransition):
            validate_transition(terminal, target)


def test_single_use_no_retry_in_place():
    # A settled (terminal) approval can never move again -- this is what
    # makes single-use hold structurally, not just by convention.
    for terminal in TERMINAL_STATES:
        with pytest.raises(IllegalTransition):
            validate_transition(terminal, "CLAIMED")
