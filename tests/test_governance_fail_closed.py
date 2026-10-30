"""Adversarial tests for fail-closed governance.

These tests describe the guarantees the kernel must hold. They fail on the
pre-change tree (permit/parameter split, fail-open without a key, execute-
then-audit, nonce burn on denial, unverified ledger load, missing COMPLETED,
exceptions that stick the state machine) and pass once those gates exist.
"""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from shards_kernel.common.errors import AuditError, StateError
from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)
from shards_kernel.execution.dispatcher import Dispatcher
from shards_kernel.execution.tools import ToolRegistry
from shards_kernel.permits import NonceRegistry, PermitBuilder, verify_permit
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.strict_kernel import StrictKernel

KEY = b"test-secret-key-32-bytes-long123"
KEYRING = {"key1": KEY}


def _config(variant: str = "strict", **overrides: object) -> KernelConfig:
    clock = overrides.pop("clock", None)
    if clock is None:
        clock = VirtualClock(initial_ms=1000)
    fields = dict(
        kernel_id="gov-test",
        variant=variant,
        clock=clock,
    )
    fields.update(overrides)
    return KernelConfig(**fields)  # type: ignore[arg-type]


def _permit(
    *,
    action: str = "echo",
    params: dict | None = None,
    constraints: dict | None = None,
    max_executions: int = 1,
    subject: str = "agent1",
    jurisdiction: str = "default",
    keyring: dict | None = None,
) -> object:
    ring = keyring or KEYRING
    return (
        PermitBuilder()
        .issuer("operator1")
        .subject(subject)
        .jurisdiction(jurisdiction)
        .action(action)
        .params({} if params is None else params)
        .constraints({} if constraints is None else constraints)
        .max_executions(max_executions)
        .valid_from_ms(0)
        .valid_until_ms(10000)
        .evidence_hash("evidence")
        .proposal_hash("proposal")
        .build(ring, "key1")
    )


class TestParamBinding(unittest.TestCase):
    """Executed parameters must be the parameters the permit authorised."""

    def setUp(self) -> None:
        self.clock = VirtualClock(initial_ms=1000)
        self.kernel = StrictKernel()
        self.kernel.boot(_config(clock=self.clock))
        self.kernel.set_keyring(dict(KEYRING))
        self.seen: list[dict] = []

        def spy(**kwargs: object) -> dict:
            self.seen.append(dict(kwargs))
            return {"ran": True, "params": dict(kwargs)}

        self.kernel._dispatcher.registry.register("spy", spy, "record params")

    def test_divergent_request_and_tool_params_are_rejected(self) -> None:
        """A permit for path=/tmp/x must not execute path=/."""
        authorised = {"path": "/tmp/x"}
        permit = _permit(action="spy", params=authorised)
        request = KernelRequest(
            request_id="req-diverge",
            ts_ms=1000,
            actor="agent1",
            intent="Delete a temp file",
            tool_call=ToolCall(name="spy", params={"path": "/"}),
            params=authorised,
        )

        receipt = self.kernel.submit(request, permit_token=permit)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertEqual(self.seen, [])
        self.assertIsNone(receipt.tool_result)
        record = self.kernel._nonce_registry.get_record(
            permit.nonce, permit.issuer, permit.subject
        )
        self.assertTrue(record is None or record.use_count == 0)

    def test_audit_records_params_that_actually_executed(self) -> None:
        """The ledger hash is of the parameters passed to the tool."""
        params = {"path": "/tmp/x"}
        permit = _permit(action="spy", params=params)
        request = KernelRequest(
            request_id="req-audit-params",
            ts_ms=1000,
            actor="agent1",
            intent="Delete a temp file",
            tool_call=ToolCall(name="spy", params=dict(params)),
            params=dict(params),
        )

        receipt = self.kernel.submit(request, permit_token=permit)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(self.seen, [params])
        expected = compute_hash_dict(params)
        entries = self.kernel.export_evidence().ledger_entries
        executed = [
            entry
            for entry in entries
            if getattr(entry, "audit_phase", None) in (None, "outcome", "intent")
            and entry.decision == Decision.ALLOW
        ]
        self.assertTrue(executed)
        for entry in executed:
            self.assertEqual(entry.params_hash, expected)

    def test_mutation_after_authorisation_does_not_execute(self) -> None:
        """A hook that rewrites tool params is rejected at the dispatcher."""
        params = {"text": "hello"}
        permit = _permit(action="echo", params=params)

        def rewrite(_context: object, tool_call: ToolCall) -> None:
            tool_call.params["text"] = "rewritten"

        self.kernel.set_runtime_hooks(before_execute=rewrite)
        request = KernelRequest(
            request_id="req-mutate",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params=dict(params)),
            params=dict(params),
        )

        receipt = self.kernel.submit(request, permit_token=permit)

        self.assertNotEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertTrue(receipt.tool_result is None or receipt.tool_result != "rewritten")
        self.assertNotIn(
            "rewritten",
            str(receipt.tool_result),
        )

    def test_dispatcher_refuses_params_that_differ_from_authorisation(self) -> None:
        """The last step before invoke re-checks the bound parameter object."""
        registry = ToolRegistry()
        called: list[dict] = []

        def spy(**kwargs: object) -> str:
            called.append(dict(kwargs))
            return "ran"

        registry.register("spy", spy)
        dispatcher = Dispatcher(registry)
        result = dispatcher.execute(
            ToolCall(name="spy", params={"path": "/"}),
            authorised_params={"path": "/tmp/x"},
        )

        self.assertFalse(result.success)
        self.assertEqual(called, [])
        self.assertIn("PARAM_BINDING", result.error or "")


class TestFailClosedDefault(unittest.TestCase):
    """No keyring must not mean no permit."""

    def test_tool_call_without_keyring_or_permit_is_denied(self) -> None:
        kernel = StrictKernel()
        kernel.boot(_config())
        called: list[str] = []

        def spy(text: str) -> str:
            called.append(text)
            return text

        kernel._dispatcher.registry.register("spy", spy)
        request = KernelRequest(
            request_id="req-nokey",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="spy", params={"text": "hello"}),
            params={"text": "hello"},
        )

        receipt = kernel.submit(request)

        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertIn("MISSING_PERMIT", receipt.error or "")
        self.assertEqual(called, [])

    def test_strict_kernel_ignores_insecure_opt_out(self) -> None:
        try:
            config = _config(allow_insecure_unpermitted_execution=True)
        except TypeError as exc:
            self.fail(
                "KernelConfig is missing allow_insecure_unpermitted_execution: "
                f"{exc}"
            )
        kernel = StrictKernel()
        kernel.boot(config)
        request = KernelRequest(
            request_id="req-strict-opt",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        receipt = kernel.submit(request)
        self.assertEqual(receipt.decision, Decision.DENY)

    def test_named_insecure_opt_out_allows_unpermitted_execution(self) -> None:
        try:
            config = _config(
                variant="permissive",
                allow_insecure_unpermitted_execution=True,
            )
        except TypeError as exc:
            self.fail(f"insecure opt-out is not configurable: {exc}")
        kernel = PermissiveKernel()
        kernel.boot(config)
        request = KernelRequest(
            request_id="req-insecure",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        receipt = kernel.submit(request)
        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.tool_result, "hello")


class TestConstraintsFailClosed(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = VirtualClock(initial_ms=1000)
        self.kernel = StrictKernel()
        self.kernel.boot(_config(clock=self.clock))
        self.kernel.set_keyring(dict(KEYRING))

    def _submit(self, constraints: dict, *, evidence: str | None = None) -> object:
        params = {"text": "hello"}
        permit = _permit(params=params, constraints=constraints)
        request = KernelRequest(
            request_id="req-constraint",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params=dict(params)),
            params=dict(params),
            evidence=evidence,
        )
        return self.kernel.submit(request, permit_token=permit)

    def test_unknown_constraint_is_rejected(self) -> None:
        receipt = self._submit({"definitely_not_a_constraint": True})
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("CONSTRAINT_UNKNOWN", receipt.error or "")

    def test_require_evidence_noop_is_rejected_without_evidence(self) -> None:
        receipt = self._submit({"require_evidence": True})
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("REQUIRE_EVIDENCE", receipt.error or "")

    def test_require_evidence_allows_when_evidence_present(self) -> None:
        receipt = self._submit(
            {"require_evidence": True},
            evidence="packet-1",
        )
        self.assertEqual(receipt.decision, Decision.ALLOW)
        self.assertEqual(receipt.tool_result, "hello")

    def test_unimplemented_constraint_is_rejected(self) -> None:
        receipt = self._submit({"allowed_domains": ["example.com"]})
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("CONSTRAINT_UNIMPLEMENTED", receipt.error or "")

    def test_direct_verify_does_not_burn_nonce_on_unknown_constraint(self) -> None:
        permit = _permit(constraints={"nope": 1})
        registry = NonceRegistry()
        result = verify_permit(
            permit,
            KEYRING,
            registry,
            current_time_ms=1000,
            current_jurisdiction="default",
            allowed_actions=frozenset({"echo", "*"}),
            request_actor="agent1",
            request_params={"text": "hello"},
        )
        self.assertEqual(result.status, Decision.DENY)
        self.assertFalse(
            registry.has_nonce(permit.nonce, permit.issuer, permit.subject)
        )


class TestPermitBudget(unittest.TestCase):
    def test_rejected_request_does_not_consume_max_executions(self) -> None:
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        kernel.set_keyring(dict(KEYRING))
        permit = _permit(params={"text": "hello"}, max_executions=1)

        bad = KernelRequest(
            request_id="req-bad",
            ts_ms=1000,
            actor="agent1",
            intent="Echo the wrong text",
            tool_call=ToolCall(name="echo", params={"text": "nope"}),
            params={"text": "nope"},
        )
        denied = kernel.submit(bad, permit_token=permit)
        self.assertEqual(denied.decision, Decision.DENY)

        good = KernelRequest(
            request_id="req-good",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        allowed = kernel.submit(good, permit_token=permit)
        self.assertEqual(allowed.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(allowed.tool_result, "hello")


class TestAuditOrdering(unittest.TestCase):
    def test_intent_is_durable_before_the_tool_runs(self) -> None:
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        kernel.set_keyring(dict(KEYRING))
        observed: dict[str, int] = {}

        def spy(text: str) -> str:
            observed["entries_before_tool"] = kernel.export_evidence().ledger_entries.__len__()
            return text

        kernel._dispatcher.registry.register("spy", spy)
        params = {"text": "hello"}
        permit = _permit(action="spy", params=params)
        request = KernelRequest(
            request_id="req-order",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="spy", params=dict(params)),
            params=dict(params),
        )

        receipt = kernel.submit(request, permit_token=permit)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertGreaterEqual(observed.get("entries_before_tool", 0), 1)
        phases = [
            getattr(entry, "audit_phase", None)
            for entry in kernel.export_evidence().ledger_entries
        ]
        self.assertIn("intent", phases)
        self.assertIn("outcome", phases)

    def test_tool_does_not_run_when_intent_append_fails(self) -> None:
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        kernel.set_keyring(dict(KEYRING))
        called: list[str] = []

        def spy(text: str) -> str:
            called.append(text)
            return text

        kernel._dispatcher.registry.register("spy", spy)

        def fail_append(*_args: object, **_kwargs: object) -> None:
            raise AuditError("disk full")

        kernel._ledger.append = fail_append  # type: ignore[method-assign]
        params = {"text": "hello"}
        permit = _permit(action="spy", params=params)
        request = KernelRequest(
            request_id="req-audit-fail",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="spy", params=dict(params)),
            params=dict(params),
        )

        with self.assertRaises(AuditError):
            kernel.submit(request, permit_token=permit)

        self.assertEqual(called, [])
        self.assertEqual(kernel.get_state(), KernelState.HALTED)


class TestLedgerLoad(unittest.TestCase):
    def test_broken_chain_halts_and_is_refused(self) -> None:
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        kernel.set_keyring(dict(KEYRING))
        permit = _permit(params={"text": "hello"})
        request = KernelRequest(
            request_id="req-load",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        self.assertEqual(
            kernel.submit(request, permit_token=permit).decision,
            Decision.ALLOW,
        )
        evidence = kernel.export_evidence()
        tampered_entry = replace(evidence.ledger_entries[0], intent="forged")
        tampered = replace(
            evidence,
            ledger_entries=(tampered_entry,) + evidence.ledger_entries[1:],
        )

        restarted = StrictKernel()
        restarted.boot(_config(clock=clock))
        with self.assertRaises(AuditError):
            restarted.load_ledger(tampered)

        self.assertEqual(restarted.get_state(), KernelState.HALTED)
        self.assertEqual(restarted.export_evidence().ledger_entries[0].intent != "forged", True)
        with self.assertRaises(StateError):
            restarted.submit(request, permit_token=permit)


class TestStateMachineGovernance(unittest.TestCase):
    def test_completed_is_part_of_the_lifecycle(self) -> None:
        self.assertTrue(
            hasattr(KernelState, "COMPLETED"),
            "KernelState is missing COMPLETED",
        )
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        request = KernelRequest(
            request_id="req-intent-only",
            ts_ms=1000,
            actor="agent1",
            intent="No tool, just an intent",
        )
        receipt = kernel.submit(request)
        self.assertEqual(receipt.decision, Decision.ALLOW)
        self.assertEqual(kernel.get_state(), KernelState.IDLE)
        log = getattr(kernel, "transition_log", None)
        self.assertIsNotNone(log)
        visited = [to.value if hasattr(to, "value") else to for _frm, to in log]
        self.assertIn("COMPLETED", visited)

    def test_unexpected_exception_halts_instead_of_sticking(self) -> None:
        kernel = StrictKernel()
        kernel.boot(_config())
        request = KernelRequest(
            request_id="req-boom",
            ts_ms=1000,
            actor="agent1",
            intent="This will explode in validation",
        )

        import shards_kernel.variants.base as base_module

        original = base_module.validate_request

        def explode(_request: KernelRequest) -> list[str]:
            raise RuntimeError("validator exploded")

        base_module.validate_request = explode
        try:
            with self.assertRaises(RuntimeError):
                kernel.submit(request)
        finally:
            base_module.validate_request = original

        self.assertEqual(kernel.get_state(), KernelState.HALTED)
        with self.assertRaises(StateError):
            kernel.submit(request)


class TestDispatcherBindingBranches(unittest.TestCase):
    def test_matching_authorisation_executes_the_bound_copy(self) -> None:
        registry = ToolRegistry()
        seen: list[dict] = []

        def spy(**kwargs: object) -> str:
            seen.append(dict(kwargs))
            kwargs["path"] = "mutated-by-tool"
            return "ok"

        registry.register("spy", spy)
        dispatcher = Dispatcher(registry)
        authorised = {"path": "/tmp/x"}
        result = dispatcher.execute(
            ToolCall(name="spy", params=dict(authorised)),
            authorised_params=authorised,
        )
        self.assertTrue(result.success)
        self.assertEqual(seen, [{"path": "/tmp/x"}])
        self.assertEqual(authorised, {"path": "/tmp/x"})

    def test_invalid_tool_call_does_not_invoke(self) -> None:
        dispatcher = Dispatcher(ToolRegistry())
        result = dispatcher.execute("not-a-call")  # type: ignore[arg-type]
        self.assertFalse(result.success)
        self.assertIn("Invalid", result.error or "")


class TestReplayOfPermitLedger(unittest.TestCase):
    def test_loaded_ledger_preserves_use_count_without_double_counting(self) -> None:
        clock = VirtualClock(initial_ms=1000)
        kernel = StrictKernel()
        kernel.boot(_config(clock=clock))
        kernel.set_keyring(dict(KEYRING))
        permit = _permit(params={"text": "hello"}, max_executions=2)
        for index in range(1):
            request = KernelRequest(
                request_id=f"req-{index}",
                ts_ms=1000,
                actor="agent1",
                intent="Echo hello",
                tool_call=ToolCall(name="echo", params={"text": "hello"}),
                params={"text": "hello"},
            )
            self.assertEqual(
                kernel.submit(request, permit_token=permit).decision,
                Decision.ALLOW,
            )
        evidence = kernel.export_evidence()
        restarted = StrictKernel()
        restarted.boot(_config(clock=clock))
        restarted.set_keyring(dict(KEYRING))
        restarted.load_ledger(evidence)
        record = restarted._nonce_registry.get_record(
            permit.nonce, permit.issuer, permit.subject
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.use_count, 1)

        again = KernelRequest(
            request_id="req-again",
            ts_ms=1100,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        self.assertEqual(
            restarted.submit(again, permit_token=permit).decision,
            Decision.ALLOW,
        )


class TestToolActionBinding(unittest.TestCase):
    def test_permit_for_a_different_tool_is_rejected_even_if_params_match_shape(self) -> None:
        kernel = StrictKernel()
        kernel.boot(_config())
        kernel.set_keyring(dict(KEYRING))
        # Same param names are not required; the action itself must match.
        permit = _permit(action="echo", params={"text": "hello"})
        request = KernelRequest(
            request_id="req-tool",
            ts_ms=1000,
            actor="agent1",
            intent="Add numbers with an echo permit",
            tool_call=ToolCall(name="add", params={"text": "hello"}),
            params={"text": "hello"},
        )
        receipt = kernel.submit(request, permit_token=permit)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertTrue(
            "ACTION" in (receipt.error or "") or "PARAMS" in (receipt.error or "")
        )


# Silence unused import if copy is needed by future cases.
_ = copy
