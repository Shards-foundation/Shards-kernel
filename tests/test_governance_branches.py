"""Branch coverage for the governance modules the fail-closed fix touches."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from kernels.audit.ledger import AuditLedger
from kernels.audit.replay import replay_and_verify, verify_evidence_bundle
from kernels.common.errors import AuditError, BootError, StateError, ToolError
from kernels.common.hashing import genesis_hash
from kernels.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    ToolCall,
    VirtualClock,
)
from kernels.common.validate import (
    check_ambiguity,
    check_param_size,
    validate_request,
    validate_tool_call,
)
from kernels.execution.dispatcher import Dispatcher, resolve_bound_params
from kernels.execution.tools import ToolRegistry, create_default_registry
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.jurisdiction.rules import (
    check_intent_length,
    check_tool_allowed,
    check_tool_call_structure,
)
from kernels.jurisdiction.rules import (
    check_param_size as check_request_param_size,
)
from kernels.permits import PermitBuilder
from kernels.variants.base import BaseKernel
from kernels.variants.permissive_kernel import PermissiveKernel
from kernels.variants.strict_kernel import StrictKernel


class _NoCopy:
    def __deepcopy__(self, _memo: dict) -> object:
        raise RuntimeError("cannot copy")


def _request(**overrides: object) -> KernelRequest:
    fields: dict[str, object] = {
        "request_id": "req",
        "ts_ms": 1,
        "actor": "alice",
        "intent": "do the thing",
    }
    fields.update(overrides)
    return KernelRequest(**fields)  # type: ignore[arg-type]


class TestDispatcherBranches(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = create_default_registry()
        self.dispatcher = Dispatcher(self.registry)

    def test_registry_and_tool_list(self) -> None:
        self.assertIs(self.dispatcher.registry, self.registry)
        self.assertIn("echo", self.dispatcher.list_available_tools())

    def test_resolve_rejects_non_dicts_and_divergence_and_uncopyable(self) -> None:
        bound, error = resolve_bound_params(["no"], {"a": 1})
        self.assertIsNone(bound)
        self.assertIn("PARAM_BINDING_MISMATCH", error or "")

        bound, error = resolve_bound_params({"a": 1}, {"a": 2})
        self.assertIsNone(bound)
        self.assertIn("differ", error or "")

        nasty = {"a": _NoCopy()}
        bound, error = resolve_bound_params(nasty, nasty)
        self.assertIsNone(bound)
        self.assertIn("could not be bound", error or "")

        bound, error = resolve_bound_params({"a": 1}, {"a": 1})
        self.assertEqual(bound, {"a": 1})
        self.assertIsNone(error)

    def test_validate_and_execute_reject_bad_shapes(self) -> None:
        self.assertEqual(
            self.dispatcher.validate_tool_call("nope"),  # type: ignore[arg-type]
            ["Invalid tool call structure"],
        )
        self.assertFalse(self.dispatcher.execute("nope").success)  # type: ignore[arg-type]
        self.assertIn(
            "required",
            ";".join(self.dispatcher.validate_tool_call(ToolCall(name="", params={}))),
        )
        missing = self.dispatcher.execute({"name": "missing", "params": {}})
        self.assertFalse(missing.success)
        self.assertIn("not registered", missing.error or "")
        bad_params = self.dispatcher.execute(
            {"name": "echo", "params": "nope"},
        )
        self.assertFalse(bad_params.success)
        self.assertIn("dictionary", bad_params.error or "")

        as_dict = self.dispatcher.execute({"name": "echo", "params": {"text": "hi"}})
        self.assertTrue(as_dict.success)
        self.assertEqual(as_dict.result, "hi")

    def test_authorised_tool_name_and_copy_failure(self) -> None:
        refused = self.dispatcher.execute(
            ToolCall(name="echo", params={"text": "hi"}),
            authorised_params={"text": "hi"},
            authorised_tool_name="add",
        )
        self.assertFalse(refused.success)
        self.assertIn("authorised tool", refused.error or "")

        nasty = {"text": _NoCopy()}
        # Equality passes; the copy that would be passed to the tool does not.
        failed = self.dispatcher.execute(
            ToolCall(name="echo", params=nasty),
            authorised_params=nasty,
            authorised_tool_name="echo",
        )
        self.assertFalse(failed.success)
        self.assertIn("could not be bound", failed.error or "")

    def test_tool_error_and_unexpected_error(self) -> None:
        def broken(**_kwargs: object) -> None:
            raise ToolError("nope")

        registry = ToolRegistry()
        registry.register("broken", broken)
        dispatcher = Dispatcher(registry)
        failed = dispatcher.execute(ToolCall(name="broken", params={}))
        self.assertFalse(failed.success)
        self.assertIn("nope", failed.error or "")

        def explode(_name: str, _params: dict) -> None:
            raise RuntimeError("boom")

        registry.invoke = explode  # type: ignore[method-assign]
        unexpected = dispatcher.execute(ToolCall(name="broken", params={}))
        self.assertFalse(unexpected.success)
        self.assertIn("Unexpected error", unexpected.error or "")


class TestValidationBranches(unittest.TestCase):
    def test_request_field_errors(self) -> None:
        cases = [
            _request(request_id=""),
            _request(request_id=1),
            _request(ts_ms=None),
            _request(ts_ms="now"),
            _request(ts_ms=-1),
            _request(actor=""),
            _request(actor=1),
            _request(intent=None),
            _request(intent=1),
            _request(params="nope"),
            _request(tool_call={"params": {}}),
            _request(tool_call={"name": 1, "params": {}}),
            _request(tool_call={"name": "", "params": {}}),
            _request(tool_call={"name": "echo", "params": []}),
            _request(tool_call=ToolCall(name="", params={})),
            _request(tool_call=ToolCall(name=1, params={})),  # type: ignore[arg-type]
        ]
        for request in cases:
            self.assertTrue(validate_request(request))

        self.assertEqual(validate_request(_request()), [])
        self.assertEqual(validate_tool_call({"name": "echo"}), [])
        self.assertEqual(validate_tool_call(ToolCall(name="echo", params={})), [])
        self.assertTrue(validate_tool_call(123))  # type: ignore[arg-type]

    def test_ambiguity_and_param_size(self) -> None:
        self.assertTrue(check_ambiguity(_request(intent="")))
        self.assertTrue(check_ambiguity(_request(intent="   ")))
        self.assertTrue(check_ambiguity(_request(intent="x" * 20), max_intent_length=5))
        empty_tool = _request(tool_call=ToolCall(name="", params={}))
        self.assertTrue(check_ambiguity(empty_tool, strict=True))
        self.assertFalse(
            any("empty name" in item for item in check_ambiguity(empty_tool, strict=False))
        )
        as_dict = _request(tool_call={"name": "", "params": {}})
        self.assertTrue(check_ambiguity(as_dict, strict=True))
        self.assertTrue(check_ambiguity(_request(params="nope")))
        self.assertTrue(check_param_size({"a": 1}, max_bytes=1000))
        self.assertFalse(check_param_size({"a": "x" * 50}, max_bytes=4))


class TestRulesBranches(unittest.TestCase):
    def test_remaining_rule_branches(self) -> None:
        open_policy = JurisdictionPolicy(
            allowed_actors=frozenset({"*"}),
            allowed_tools=frozenset({"echo"}),
            allow_intent_only=True,
            max_param_bytes=8,
            max_intent_length=4,
        )
        closed = JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}),
            allowed_tools=frozenset({"echo"}),
            allow_intent_only=False,
        )
        self.assertEqual(
            check_tool_allowed(_request(tool_call=None), open_policy),
            [],
        )
        self.assertEqual(
            check_tool_allowed(_request(tool_call=None), closed),
            [],
        )
        as_dict = _request(tool_call={"name": "other", "params": {}})
        self.assertTrue(check_tool_allowed(as_dict, open_policy))

        self.assertEqual(check_request_param_size(_request(params=None), open_policy), [])
        oversized = _request(params={"k": "value-too-big"})
        self.assertTrue(check_request_param_size(oversized, open_policy))
        self.assertTrue(
            check_request_param_size(_request(params={"a": object()}), open_policy)
        )
        self.assertTrue(check_intent_length(_request(intent="too-long"), open_policy))
        self.assertEqual(check_intent_length(_request(intent="ok"), closed), [])

        self.assertTrue(
            check_tool_call_structure(_request(tool_call=ToolCall(name="", params={})))
        )
        self.assertTrue(
            check_tool_call_structure(_request(tool_call={"name": "", "params": []}))
        )
        self.assertTrue(check_tool_call_structure(_request(tool_call="nope")))  # type: ignore[arg-type]
        self.assertEqual(check_tool_call_structure(_request(tool_call=None)), [])


class TestLedgerAndReplayBranches(unittest.TestCase):
    def test_properties_load_paths_and_append_failure(self) -> None:
        ledger = AuditLedger("kid", "strict")
        self.assertEqual(ledger.kernel_id, "kid")
        self.assertEqual(ledger.variant, "strict")
        entry = ledger.append(
            request_id="req",
            actor="alice",
            intent="one",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.COMPLETED,
            ts_ms=1,
            permit_denial_reasons=("NOPE",),
            audit_phase="outcome",
        )
        self.assertTrue(replay_and_verify(ledger.to_list())[0])

        fresh = AuditLedger("kid", "strict")
        fresh.load_verified((), genesis_hash())
        self.assertEqual(fresh.length, 0)
        with self.assertRaises(AuditError):
            fresh.load_verified((), "not-genesis")

        with self.assertRaises(AuditError):
            ledger.load_verified((entry,), entry.entry_hash)
        self.assertEqual(ledger.length, 1)

        gapped = replace(entry, ledger_seq=3)
        empty = AuditLedger("kid", "strict")
        with self.assertRaises(AuditError):
            empty.load_verified((gapped,), gapped.entry_hash)
        self.assertEqual(empty.length, 0)

        forged = replace(entry, intent="forged")
        with self.assertRaises(AuditError):
            empty.load_verified((forged,), forged.entry_hash)
        self.assertEqual(empty.length, 0)

        installed = AuditLedger("kid", "strict")
        installed.load_verified((entry,), entry.entry_hash)
        self.assertEqual(installed.length, 1)

        with self.assertRaises(AuditError):
            ledger.append(
                request_id="req",
                actor="alice",
                intent="bad",
                decision=Decision.DENY,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=2,
                params={"a": object()},
            )

    def test_replay_empty_bundle_and_listed_denial_reasons(self) -> None:
        result = verify_evidence_bundle({"ledger_entries": [], "root_hash": genesis_hash()})
        self.assertTrue(result.is_valid)
        self.assertEqual(result.computed_root_hash, genesis_hash())
        self.assertEqual(result.entries_verified, 0)


class TestKernelDefensiveBranches(unittest.TestCase):
    def test_unbooted_kernel_refuses_operations(self) -> None:
        kernel = StrictKernel()
        self.assertEqual(kernel.get_state(), KernelState.BOOTING)
        request = _request()
        with self.assertRaises(StateError):
            kernel.submit(request)
        with self.assertRaises(StateError):
            kernel.halt("nope")
        with self.assertRaises(StateError):
            kernel.export_evidence()
        with self.assertRaises(StateError):
            kernel.load_ledger(None)  # type: ignore[arg-type]
        with self.assertRaises(StateError):
            kernel.set_runtime_hooks()

    def test_double_boot_and_step_and_policy(self) -> None:
        kernel = StrictKernel()
        config = KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1))
        kernel.boot(config)
        with self.assertRaises(BootError):
            kernel.boot(config)
        self.assertIsNone(kernel.step())
        policy = JurisdictionPolicy.strict()
        kernel.set_policy(policy)
        self.assertIs(kernel.policy, policy)

    def test_dict_tool_call_and_bad_shapes_are_denied(self) -> None:
        kernel = StrictKernel()
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1)))
        keyring = {"key1": b"test-secret-key-32-bytes-long123"}
        kernel.set_keyring(keyring)
        permit = (
            PermitBuilder()
            .issuer("operator1")
            .subject("alice")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hi"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10)
            .evidence_hash("e")
            .proposal_hash("p")
            .build(keyring, "key1")
        )
        request = _request(
            actor="alice",
            intent="Echo hi",
            tool_call={"name": "echo", "params": {"text": "hi"}},
            params={"text": "hi"},
        )
        receipt = kernel.submit(request, permit_token=permit)
        self.assertEqual(receipt.tool_result, "hi")

        bad = kernel.submit(_request(tool_call=123, params={}))  # type: ignore[arg-type]
        self.assertEqual(bad.decision, Decision.DENY)
        self.assertIn("invalid structure", (bad.error or "").lower())
        self.assertEqual(kernel.get_state(), KernelState.IDLE)

    def test_commit_refusal_does_not_execute(self) -> None:
        kernel = StrictKernel()
        clock = VirtualClock(1000)
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=clock))
        keyring = {"key1": b"test-secret-key-32-bytes-long123"}
        kernel.set_keyring(keyring)
        called: list[str] = []

        def spy(text: str) -> str:
            called.append(text)
            return text

        kernel._dispatcher.registry.register("spy", spy)
        permit = (
            PermitBuilder()
            .issuer("operator1")
            .subject("alice")
            .jurisdiction("default")
            .action("spy")
            .params({"text": "hi"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("e")
            .proposal_hash("p")
            .build(keyring, "key1")
        )
        kernel._nonce_registry.check_and_record = (  # type: ignore[method-assign]
            lambda **_kwargs: False
        )
        receipt = kernel.submit(
            _request(
                actor="alice",
                intent="Echo hi",
                tool_call=ToolCall(name="spy", params={"text": "hi"}),
                params={"text": "hi"},
            ),
            permit_token=permit,
        )
        self.assertIn("REPLAY_DETECTED", receipt.error or "")
        self.assertEqual(called, [])

    def test_fail_closed_flag_off_still_audits_empty_intent_when_opted_in(self) -> None:
        kernel = PermissiveKernel()
        kernel.boot(
            KernelConfig(
                kernel_id="k",
                variant="permissive",
                clock=VirtualClock(1),
                fail_closed=False,
            )
        )
        receipt = kernel.submit(_request(intent=""))
        # Empty intent is ambiguous, but fail_closed=False skips that denial.
        # Jurisdiction then rejects the empty intent as a missing field.
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertNotIn("Ambiguity", receipt.error or "")
        self.assertIn("intent", (receipt.error or "").lower())

    def test_insecure_opt_out_still_rejects_divergent_params(self) -> None:
        kernel = PermissiveKernel()
        kernel.boot(
            KernelConfig(
                kernel_id="k",
                variant="permissive",
                clock=VirtualClock(1),
                allow_insecure_unpermitted_execution=True,
            )
        )
        receipt = kernel.submit(
            _request(
                tool_call=ToolCall(name="echo", params={"text": "a"}),
                params={"text": "b"},
            )
        )
        self.assertIn("PARAM_BINDING_MISMATCH", receipt.error or "")


def _permit(action: str, params: dict[str, object]) -> object:
    keyring = {"key1": b"test-secret-key-32-bytes-long123"}
    return (
        PermitBuilder()
        .issuer("operator1")
        .subject("alice")
        .jurisdiction("default")
        .action(action)
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("e")
        .proposal_hash("p")
        .build(keyring, "key1"),
        keyring,
    )


class _RewriteToolParams(StrictKernel):
    """Rewrites the tool call after the permit has already been checked."""

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        tool_call = request.tool_call
        if isinstance(tool_call, ToolCall):
            tool_call.params["text"] = "rewritten"
        return []


class _RewritePermitParams(StrictKernel):
    """Changes the authorised parameter set after verification."""

    def __init__(self) -> None:
        super().__init__()
        self.held_permit: object | None = None

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        permit = self.held_permit
        if permit is not None:
            permit.params.clear()  # type: ignore[attr-defined]
            permit.params["text"] = "other"  # type: ignore[attr-defined]
        return []


class _RevokeInsecureOptOut(PermissiveKernel):
    """Turns the dev opt-out off after the first permit check."""

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        if self._config is not None:
            self._config.allow_insecure_unpermitted_execution = False
        return []


class TestBaseKernelDefensiveBranches(unittest.TestCase):
    def test_unbooted_helpers_refuse(self) -> None:
        kernel = BaseKernel()
        with self.assertRaises(StateError):
            _ = kernel.config
        with self.assertRaises(StateError):
            _ = kernel.policy
        with self.assertRaises(StateError):
            kernel._rebuild_nonce_registry()
        kernel._halt_on_fault("no machine yet")
        self.assertTrue(kernel._is_strict_ambiguity())
        self.assertEqual(kernel._check_variant_requirements(_request()), [])

        _name, _params, error = kernel._tool_parts(_request(tool_call=123))  # type: ignore[arg-type]
        self.assertIn("Invalid tool call", error or "")
        _name, _params, error = kernel._tool_parts(
            _request(tool_call={"name": "echo", "params": "nope"})  # type: ignore[arg-type]
        )
        self.assertIn("PARAM_BINDING_MISMATCH", error or "")

        request = _request()
        with self.assertRaises(StateError):
            kernel._submit_bound(request, None)
        with self.assertRaises(StateError):
            kernel._transition_executing()
        with self.assertRaises(StateError):
            kernel._complete_request()
        with self.assertRaises(StateError):
            kernel._append_record(
                request,
                state_from=KernelState.IDLE,
                decision=Decision.DENY,
                state_to=KernelState.COMPLETED,
                audit_phase="outcome",
            )
        with self.assertRaises(StateError):
            kernel._deny_request(request, KernelState.IDLE, "no")
        with self.assertRaises(StateError):
            kernel._fail_request(request, KernelState.IDLE, "no")
        with self.assertRaises(StateError):
            kernel._deny_permit(request, KernelState.IDLE, "no", ["MISSING_PERMIT"])

    def test_booted_guards_and_halt_without_ledger(self) -> None:
        kernel = StrictKernel()
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1)))
        with self.assertRaises(StateError):
            kernel._transition_executing()
        with self.assertRaises(StateError):
            kernel._complete_request()
        kernel._ledger = None
        kernel._halt_on_fault("ledger disappeared")
        self.assertEqual(kernel.get_state(), KernelState.HALTED)

    def test_bypassed_validation_still_rejects_a_bad_tool_call(self) -> None:
        kernel = StrictKernel()
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1)))
        with patch("kernels.variants.base.validate_request", return_value=[]), patch(
            "kernels.variants.base.check_ambiguity", return_value=[]
        ):
            receipt = kernel._submit_bound(
                _request(tool_call=123, params={}),  # type: ignore[arg-type]
                None,
            )
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("Invalid tool call", receipt.error or "")
        self.assertEqual(kernel.get_state(), KernelState.IDLE)

    def test_post_check_param_rewrite_is_rejected(self) -> None:
        kernel = _RewriteToolParams()
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1)))
        permit, keyring = _permit("spy", {"text": "hi"})
        kernel.set_keyring(keyring)  # type: ignore[arg-type]
        called: list[str] = []
        kernel._dispatcher.registry.register("spy", lambda text: called.append(text) or text)
        receipt = kernel.submit(
            _request(
                actor="alice",
                intent="Echo hi",
                tool_call=ToolCall(name="spy", params={"text": "hi"}),
                params={"text": "hi"},
            ),
            permit_token=permit,  # type: ignore[arg-type]
        )
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("PARAM_BINDING_MISMATCH", receipt.error or "")
        self.assertEqual(called, [])

    def test_post_check_permit_rewrite_is_rejected(self) -> None:
        kernel = _RewritePermitParams()
        kernel.boot(KernelConfig(kernel_id="k", variant="strict", clock=VirtualClock(1)))
        permit, keyring = _permit("spy", {"text": "hi"})
        kernel.held_permit = permit
        kernel.set_keyring(keyring)  # type: ignore[arg-type]
        called: list[str] = []
        kernel._dispatcher.registry.register("spy", lambda text: called.append(text) or text)
        receipt = kernel.submit(
            _request(
                actor="alice",
                intent="Echo hi",
                tool_call=ToolCall(name="spy", params={"text": "hi"}),
                params={"text": "hi"},
            ),
            permit_token=permit,  # type: ignore[arg-type]
        )
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("PARAM_BINDING_MISMATCH", receipt.error or "")
        self.assertEqual(called, [])

    def test_revoking_the_dev_opt_out_before_execution_denies(self) -> None:
        kernel = _RevokeInsecureOptOut()
        kernel.boot(
            KernelConfig(
                kernel_id="k",
                variant="permissive",
                clock=VirtualClock(1),
                allow_insecure_unpermitted_execution=True,
            )
        )
        called: list[str] = []
        kernel._dispatcher.registry.register("spy", lambda text: called.append(text) or text)
        receipt = kernel.submit(
            _request(
                tool_call=ToolCall(name="spy", params={"text": "hi"}),
                params={"text": "hi"},
            )
        )
        self.assertIn("MISSING_PERMIT", receipt.error or "")
        self.assertEqual(called, [])
