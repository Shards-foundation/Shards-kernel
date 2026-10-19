"""State transition definitions for Kernels.

Defines the allowed state transitions and provides functions to check
transition validity.
"""

from typing import Optional

from kernels.common.types import KernelState


# Allowed transitions: from_state -> set of allowed to_states
ALLOWED_TRANSITIONS: dict[KernelState, frozenset[KernelState]] = {
    KernelState.BOOTING: frozenset({KernelState.IDLE, KernelState.HALTED}),
    KernelState.IDLE: frozenset({KernelState.VALIDATING, KernelState.HALTED}),
    KernelState.VALIDATING: frozenset(
        {
            KernelState.ARBITRATING,
            KernelState.AUDITING,  # For validation failures
            KernelState.HALTED,
        }
    ),
    KernelState.ARBITRATING: frozenset(
        {
            KernelState.EXECUTING,
            KernelState.AUDITING,  # For denied requests and pre-execution intent
            KernelState.HALTED,
        }
    ),
    KernelState.EXECUTING: frozenset(
        {
            KernelState.AUDITING,
            KernelState.HALTED,
        }
    ),
    KernelState.AUDITING: frozenset(
        {
            KernelState.EXECUTING,  # Intent record is durable; the tool may run
            KernelState.COMPLETED,  # Final audit record is durable
            KernelState.HALTED,
        }
    ),
    KernelState.COMPLETED: frozenset(
        {
            KernelState.IDLE,
            KernelState.HALTED,
        }
    ),
    KernelState.HALTED: frozenset(),  # Terminal state, no transitions allowed
}


def can_transition(from_state: KernelState, to_state: KernelState) -> bool:
    """Check if a transition is allowed.

    Args:
        from_state: Current state.
        to_state: Target state.

    Returns:
        True if transition is allowed, False otherwise.
    """
    allowed = ALLOWED_TRANSITIONS.get(from_state, frozenset())
    return to_state in allowed


def get_next_states(state: KernelState) -> frozenset[KernelState]:
    """Get all states reachable from the given state.

    Args:
        state: Current state.

    Returns:
        Frozenset of reachable states.
    """
    return ALLOWED_TRANSITIONS.get(state, frozenset())


def is_terminal(state: KernelState) -> bool:
    """Check if a state is terminal (no outgoing transitions).

    Args:
        state: State to check.

    Returns:
        True if terminal, False otherwise.
    """
    return len(ALLOWED_TRANSITIONS.get(state, frozenset())) == 0


def validate_transition_path(path: list[KernelState]) -> tuple[bool, Optional[str]]:
    """Validate a sequence of state transitions.

    Args:
        path: List of states representing a transition path.

    Returns:
        Tuple of (is_valid, error_message or None).
    """
    if len(path) < 2:
        return True, None

    for i in range(len(path) - 1):
        from_state = path[i]
        to_state = path[i + 1]
        if not can_transition(from_state, to_state):
            return False, f"Invalid transition: {from_state.value} -> {to_state.value}"

    return True, None
