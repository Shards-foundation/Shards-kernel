"""State machine implementation for Kernels."""

from shards_kernel.state.machine import StateMachine
from shards_kernel.state.transitions import (
    ALLOWED_TRANSITIONS,
    can_transition,
    get_next_states,
)

__all__ = [
    "StateMachine",
    "ALLOWED_TRANSITIONS",
    "can_transition",
    "get_next_states",
]
