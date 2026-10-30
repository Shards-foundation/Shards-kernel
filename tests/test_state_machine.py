"""Tests for state machine."""

import unittest

from shards_kernel.common.types import KernelState
from shards_kernel.common.errors import StateError
from shards_kernel.state.machine import StateMachine
from shards_kernel.state.transitions import (
    can_transition,
    get_next_states,
    is_terminal,
    validate_transition_path,
)


class TestTransitions(unittest.TestCase):
    """Test cases for transition definitions."""

    def test_booting_to_idle(self) -> None:
        """BOOTING can transition to IDLE."""
        self.assertTrue(can_transition(KernelState.BOOTING, KernelState.IDLE))

    def test_idle_to_validating(self) -> None:
        """IDLE can transition to VALIDATING."""
        self.assertTrue(can_transition(KernelState.IDLE, KernelState.VALIDATING))

    def test_halted_is_terminal(self) -> None:
        """HALTED is a terminal state."""
        self.assertTrue(is_terminal(KernelState.HALTED))

    def test_idle_not_terminal(self) -> None:
        """IDLE is not terminal."""
        self.assertFalse(is_terminal(KernelState.IDLE))

    def test_invalid_transition(self) -> None:
        """Invalid transitions return False."""
        self.assertFalse(can_transition(KernelState.IDLE, KernelState.EXECUTING))

    def test_get_next_states(self) -> None:
        """get_next_states returns valid targets."""
        next_states = get_next_states(KernelState.IDLE)
        self.assertIn(KernelState.VALIDATING, next_states)
        self.assertIn(KernelState.HALTED, next_states)

    def test_validate_transition_path_valid(self) -> None:
        """Valid path validates successfully."""
        path = [
            KernelState.BOOTING,
            KernelState.IDLE,
            KernelState.VALIDATING,
            KernelState.ARBITRATING,
        ]
        is_valid, error = validate_transition_path(path)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_transition_path_invalid(self) -> None:
        """Invalid path returns error."""
        path = [
            KernelState.BOOTING,
            KernelState.EXECUTING,  # Invalid: BOOTING cannot go to EXECUTING
        ]
        is_valid, error = validate_transition_path(path)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)


class TestStateMachine(unittest.TestCase):
    """Test cases for StateMachine class."""

    def test_initial_state(self) -> None:
        """Machine starts in BOOTING state."""
        machine = StateMachine()
        self.assertEqual(machine.state, KernelState.BOOTING)

    def test_transition(self) -> None:
        """Valid transition updates state."""
        machine = StateMachine()
        prev = machine.transition(KernelState.IDLE)
        self.assertEqual(prev, KernelState.BOOTING)
        self.assertEqual(machine.state, KernelState.IDLE)

    def test_invalid_transition_raises(self) -> None:
        """Invalid transition raises StateError."""
        machine = StateMachine()
        with self.assertRaises(StateError):
            machine.transition(KernelState.EXECUTING)

    def test_halt(self) -> None:
        """Halt transitions to HALTED."""
        machine = StateMachine()
        machine.transition(KernelState.IDLE)
        machine.halt()
        self.assertEqual(machine.state, KernelState.HALTED)
        self.assertTrue(machine.is_halted)

    def test_halt_from_terminal_raises(self) -> None:
        """Halting from HALTED raises StateError."""
        machine = StateMachine()
        machine.transition(KernelState.IDLE)
        machine.halt()
        with self.assertRaises(StateError):
            machine.halt()

    def test_transition_count(self) -> None:
        """Transition count increments correctly."""
        machine = StateMachine()
        self.assertEqual(machine.transition_count, 0)
        machine.transition(KernelState.IDLE)
        self.assertEqual(machine.transition_count, 1)

    def test_assert_state(self) -> None:
        """assert_state passes for correct state."""
        machine = StateMachine()
        machine.assert_state(KernelState.BOOTING)

    def test_assert_state_fails(self) -> None:
        """assert_state raises for wrong state."""
        machine = StateMachine()
        with self.assertRaises(StateError):
            machine.assert_state(KernelState.IDLE)

    def test_reset(self) -> None:
        """Reset returns machine to initial state."""
        machine = StateMachine()
        machine.transition(KernelState.IDLE)
        machine.reset()
        self.assertEqual(machine.state, KernelState.BOOTING)
        self.assertEqual(machine.transition_count, 0)


if __name__ == "__main__":
    unittest.main()
