"""State machine implementation for Kernels.

The state machine enforces deterministic state transitions and fail-closed
behavior. Invalid transitions raise StateError.
"""

from typing import Callable, Optional

from shards_kernel.common.types import KernelState
from shards_kernel.common.errors import StateError
from shards_kernel.state.transitions import can_transition, is_terminal


class StateMachine:
    """Deterministic state machine with fail-closed semantics.

    The state machine starts in BOOTING state and must be explicitly
    transitioned to IDLE before accepting requests.
    """

    def __init__(
        self,
        initial_state: KernelState = KernelState.BOOTING,
        on_transition: Optional[Callable[[KernelState, KernelState], None]] = None,
    ) -> None:
        """Initialize the state machine.

        Args:
            initial_state: Starting state. Defaults to BOOTING.
            on_transition: Optional callback invoked on each transition.
        """
        self._state = initial_state
        self._on_transition = on_transition
        self._transition_count = 0

    @property
    def state(self) -> KernelState:
        """Return the current state."""
        return self._state

    @property
    def transition_count(self) -> int:
        """Return the number of transitions that have occurred."""
        return self._transition_count

    @property
    def is_halted(self) -> bool:
        """Check if the machine is in HALTED state."""
        return self._state == KernelState.HALTED

    @property
    def is_terminal(self) -> bool:
        """Check if the machine is in a terminal state."""
        return is_terminal(self._state)

    def transition(self, to_state: KernelState) -> KernelState:
        """Transition to a new state.

        Args:
            to_state: Target state.

        Returns:
            The previous state.

        Raises:
            StateError: If transition is not allowed.
        """
        if self.is_terminal:
            raise StateError(
                f"Cannot transition from terminal state {self._state.value}"
            )

        if not can_transition(self._state, to_state):
            raise StateError(
                f"Invalid transition: {self._state.value} -> {to_state.value}"
            )

        from_state = self._state
        self._state = to_state
        self._transition_count += 1

        if self._on_transition:
            self._on_transition(from_state, to_state)

        return from_state

    def halt(self) -> KernelState:
        """Transition to HALTED state from any non-terminal state.

        Returns:
            The previous state.

        Raises:
            StateError: If already in terminal state.
        """
        if self.is_terminal:
            raise StateError(f"Cannot halt from terminal state {self._state.value}")

        return self.transition(KernelState.HALTED)

    def reset(self, to_state: KernelState = KernelState.BOOTING) -> None:
        """Reset the state machine.

        This is a privileged operation that bypasses transition rules.
        Use only for testing or re-initialization.

        Args:
            to_state: State to reset to. Defaults to BOOTING.
        """
        self._state = to_state
        self._transition_count = 0

    def assert_state(self, expected: KernelState) -> None:
        """Assert that the machine is in an expected state.

        Args:
            expected: Expected state.

        Raises:
            StateError: If not in expected state.
        """
        if self._state != expected:
            raise StateError(
                f"Expected state {expected.value}, but in {self._state.value}"
            )

    def assert_not_halted(self) -> None:
        """Assert that the machine is not halted.

        Raises:
            StateError: If halted.
        """
        if self.is_halted:
            raise StateError("Kernel is halted")
