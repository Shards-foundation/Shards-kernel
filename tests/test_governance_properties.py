"""Property tests for fail-closed execution invariants."""

from __future__ import annotations

import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from shards_kernel.common.errors import StateError
from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    ToolCall,
    VirtualClock,
)
from shards_kernel.permits import NonceRegistry, PermitBuilder, verify_permit
from shards_kernel.state.machine import StateMachine
from shards_kernel.state.transitions import can_transition
from shards_kernel.variants.strict_kernel import StrictKernel

_KNOWN_CONSTRAINTS = frozenset(
    {
        "forbidden_params",
        "require_evidence",
        "max_time_ms",
        "max_memory_mb",
        "allowed_domains",
    }
)
_KEYRING = {"key1": b"test-secret-key-32-bytes-long123"}


def _permit(params: dict[str, str]) -> object:
    return (
        PermitBuilder()
        .issuer("operator1")
        .subject("agent1")
        .jurisdiction("default")
        .action("echo")
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("evidence")
        .proposal_hash("proposal")
        .build(_KEYRING, "key1")
    )


class TestExecutionInvariant(unittest.TestCase):
    """No strict-kernel path reaches EXECUTING without a bound permit."""

    @settings(max_examples=25, deadline=None)
    @given(
        text=st.text(alphabet="abc", min_size=1, max_size=6),
        diverge=st.booleans(),
    )
    def test_executing_requires_a_bound_permit(self, text: str, diverge: bool) -> None:
        kernel = StrictKernel()
        kernel.boot(
            KernelConfig(
                kernel_id="prop",
                variant="strict",
                clock=VirtualClock(1000),
            )
        )
        kernel.set_keyring(dict(_KEYRING))
        authorised = {"text": text}
        executed = {"text": text + "x"} if diverge else dict(authorised)
        permit = _permit(authorised)
        request = KernelRequest(
            request_id="req-prop",
            ts_ms=1000,
            actor="agent1",
            intent="Echo a value",
            tool_call=ToolCall(name="echo", params=executed),
            params=dict(authorised) if diverge else dict(executed),
        )
        # When the two sides differ, request.params stays on the permit and
        # tool_call.params does not. When they match, both equal the permit.
        if not diverge:
            request = KernelRequest(
                request_id="req-prop",
                ts_ms=1000,
                actor="agent1",
                intent="Echo a value",
                tool_call=ToolCall(name="echo", params=dict(authorised)),
                params=dict(authorised),
            )

        receipt = kernel.submit(request, permit_token=permit)
        visited = [state_to.value for _state_from, state_to in kernel.transition_log]

        if diverge:
            self.assertEqual(receipt.decision, Decision.DENY)
            self.assertNotIn("EXECUTING", visited)
            self.assertIsNone(receipt.tool_result)
            return

        self.assertEqual(receipt.decision, Decision.ALLOW)
        self.assertIn("EXECUTING", visited)
        intent = [
            entry
            for entry in kernel.export_evidence().ledger_entries
            if entry.audit_phase == "intent"
        ]
        self.assertEqual(len(intent), 1)
        self.assertEqual(intent[0].permit_verification, "INTENT")
        self.assertEqual(intent[0].permit_digest, permit.permit_id)
        self.assertLess(
            visited.index("EXECUTING"),
            len(visited),
        )
        # The intent record is written before EXECUTING is entered.
        self.assertLess(
            visited.index("AUDITING"),
            visited.index("EXECUTING"),
        )

    @settings(max_examples=20, deadline=None)
    @given(
        key=st.from_regex(r"[a-z]{1,8}", fullmatch=True).filter(
            lambda item: item not in _KNOWN_CONSTRAINTS
        )
    )
    def test_unknown_constraint_keys_never_authorise(self, key: str) -> None:
        permit = (
            PermitBuilder()
            .issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "a"})
            .constraints({key: True})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10_000)
            .evidence_hash("evidence")
            .proposal_hash("proposal")
            .build(_KEYRING, "key1")
        )
        registry = NonceRegistry()
        result = verify_permit(
            permit,
            _KEYRING,
            registry,
            current_time_ms=1000,
            current_jurisdiction="default",
            allowed_actions=frozenset({"echo"}),
            request_actor="agent1",
            request_params={"text": "a"},
            commit_use=True,
        )
        self.assertEqual(result.status, Decision.DENY)
        self.assertTrue(any(reason.startswith("CONSTRAINT_UNKNOWN:") for reason in result.reasons))
        self.assertFalse(registry.has_nonce(permit.nonce, permit.issuer, permit.subject))


class TestStateMachineProperties(unittest.TestCase):
    @settings(max_examples=40, deadline=None)
    @given(st.lists(st.sampled_from(list(KernelState)), max_size=10))
    def test_executing_only_follows_an_audit_or_arbitration_state(
        self, targets: list[KernelState]
    ) -> None:
        machine = StateMachine()
        previous = machine.state
        for target in targets:
            if not can_transition(machine.state, target):
                continue
            machine.transition(target)
            if target == KernelState.EXECUTING:
                self.assertIn(
                    previous,
                    (KernelState.ARBITRATING, KernelState.AUDITING),
                )
            previous = machine.state
        if machine.is_halted:
            with self.assertRaises(StateError):
                machine.transition(KernelState.IDLE)
