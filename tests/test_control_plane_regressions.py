"""Regression tests for permit, evidence and dispatch boundaries."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from threading import Event, Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel import (
    AuditError,
    BootError,
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    StateError,
    ToolCall,
    VirtualClock,
    replay_and_verify,
    verify_evidence_bundle,
)
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.async_support.async_kernel import (
    AsyncKernel,
    submit_batch,
    submit_with_retry,
    submit_with_timeout,
)
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.hashing import compute_hash_dict, genesis_hash
from shards_kernel.execution.dispatcher import (
    Dispatcher,
    resolve_bound_params,
    resolve_effective_params,
)
from shards_kernel.execution.tools import ToolRegistry
from shards_kernel.integrations.wire import request_from_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel
from shards_kernel.variants.strict_kernel import StrictKernel


KEY_ID = "test-key"
AUDIENCE = "regression-kernel"


@pytest.fixture
def signed_kernel():
    key = Ed25519PrivateKey.generate()  # ephemeral test key only
    clock = VirtualClock(1000)
    kernel = StrictKernel()
    kernel.boot(KernelConfig(AUDIENCE, "strict", clock=clock))
    kernel.set_policy(
        JurisdictionPolicy(allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"}))
    )
    kernel.set_public_verifiers(
        {KEY_ID: PublicVerificationKey("operator", AUDIENCE, key.public_key().public_bytes_raw())}
    )
    seen = []

    def probe(amount=99):
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.register("probe", probe)
    return kernel, key, clock, seen


def signed_permit(key, params, *, constraints=None, valid_until=2000):
    unsigned = (
        PermitBuilder()
        .issuer("operator")
        .subject("agent")
        .jurisdiction("default")
        .action("probe")
        .params(params)
        .constraints(constraints or {})
        .max_executions(1)
        .valid_from_ms(1)
        .valid_until_ms(valid_until)
        .proposal_hash("test-proposal")
        .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
    )
    return sign_v2_permit(unsigned, key)


def request(params, *, request_id="request"):
    return KernelRequest(
        request_id, 1000, "agent", "local probe", ToolCall("probe", params), params
    )


def one_entry():
    ledger = AuditLedger("regression", "strict")
    ledger.append(
        request_id="r",
        actor="agent",
        intent="local",
        decision=Decision.DENY,
        state_from=KernelState.IDLE,
        state_to=KernelState.COMPLETED,
        ts_ms=1000,
    )
    return ledger.to_list(), ledger.root_hash


def test_empty_ledger_requires_matching_root_when_one_is_supplied():
    assert replay_and_verify([]) == (True, [])
    assert replay_and_verify([], genesis_hash()) == (True, [])
    assert replay_and_verify([], "f" * 64)[0] is False


def test_public_evidence_verifier_rejects_missing_fields_but_accepts_empty_genesis():
    assert not verify_evidence_bundle({}).is_valid
    assert not verify_evidence_bundle({"root_hash": genesis_hash()}).is_valid
    assert not verify_evidence_bundle({"ledger_entries": []}).is_valid
    assert verify_evidence_bundle({"ledger_entries": [], "root_hash": genesis_hash()}).is_valid


def test_public_evidence_verifier_fails_closed_on_invalid_shapes_and_sequence():
    entries, root = one_entry()
    malformed = {"ledger_entries": ["not a mapping"], "root_hash": root}
    assert not verify_evidence_bundle(malformed).is_valid
    changed = deepcopy(entries)
    changed[0]["ledger_seq"] = 999
    assert not verify_evidence_bundle({"ledger_entries": changed, "root_hash": root}).is_valid
    assert verify_evidence_bundle({"ledger_entries": entries, "root_hash": root}).is_valid


def test_evidence_replay_rejects_non_json_and_conflicting_bundle_shapes():
    entries, root = one_entry()
    assert not replay_and_verify(None)[0]
    assert not replay_and_verify([], 1)[0]
    assert not verify_evidence_bundle(None).is_valid
    malformed = deepcopy(entries)
    malformed[0]["entry_hash"] = 7
    invalid = verify_evidence_bundle({"ledger_entries": malformed, "root_hash": root})
    assert not invalid.is_valid
    assert invalid.computed_root_hash == ""
    malformed = deepcopy(entries)
    malformed[0]["intent"] = object()
    assert not verify_evidence_bundle({"ledger_entries": malformed, "root_hash": root}).is_valid
    malformed = deepcopy(entries)
    del malformed[0]["actor"]
    assert not verify_evidence_bundle({"ledger_entries": malformed, "root_hash": root}).is_valid
    for extra in ({"schema": "unknown"}, {"entries": []}, {"entry_count": 2}):
        assert not verify_evidence_bundle(
            {"ledger_entries": entries, "root_hash": root, **extra}
        ).is_valid
    assert verify_evidence_bundle(
        {"ledger_entries": entries, "root_hash": root, "entry_count": 1}
    ).is_valid


def test_signature_binding_handles_variadic_and_unsupported_defaults():
    def variadic(required, /, *args, **kwargs):
        pass

    def positional_default(value=1, /):
        pass

    def invalid_default(value=object()):
        pass

    assert "cannot bind" in resolve_effective_params(variadic, {"extra": 3})[1]
    assert "positional-only" in resolve_effective_params(positional_default, {})[1]
    assert "JSON" in resolve_effective_params(invalid_default, {})[1]
    registry = ToolRegistry()
    registry.register("echo", lambda **kwargs: kwargs)
    assert Dispatcher(registry).validate_tool_call({"name": "echo", "params": []})


def test_signed_permit_does_not_treat_boolean_as_integer(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    result = kernel.submit(request({"amount": True}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.DENY
    assert seen == []


def test_request_and_tool_binding_rejects_bool_integer_alias():
    bound, error = resolve_bound_params({"amount": 1}, {"amount": True})
    assert bound is None
    assert "PARAM_BINDING_MISMATCH" in error


def test_dispatcher_rejects_bool_integer_alias():
    registry = ToolRegistry()
    seen = []
    registry.register("probe", lambda amount: seen.append(amount))
    result = Dispatcher(registry).execute(
        ToolCall("probe", {"amount": True}), authorised_params={"amount": 1}
    )
    assert not result.success
    assert seen == []


def test_signed_permit_cannot_select_unauthorised_handler_default(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    result = kernel.submit(request({}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.DENY
    assert seen == []


def test_authorised_handler_default_is_audited_and_executed(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    result = kernel.submit(request({}), signed_permit(key, {"amount": 99}))
    assert result.decision is Decision.ALLOW
    assert seen == [99]
    assert kernel.export_evidence().ledger_entries[0].params_hash == compute_hash_dict(
        {"amount": 99}
    )


def test_signed_permit_still_allows_safe_subset(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    result = kernel.submit(
        request({"amount": 1}), signed_permit(key, {"amount": 1, "unused": "ok"})
    )
    assert result.decision is Decision.ALLOW
    assert seen == [1]


def test_signed_permit_expiring_before_dispatch_is_denied(signed_kernel):
    kernel, key, clock, seen = signed_kernel
    kernel.set_runtime_hooks(before_execute=lambda _ctx, _call: clock.advance(1001))
    result = kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.DENY
    assert "EXPIRED" in (result.error or "")
    assert seen == []


def test_signed_permit_remains_valid_at_inclusive_expiry_boundary(signed_kernel):
    kernel, key, clock, seen = signed_kernel
    kernel.set_runtime_hooks(before_execute=lambda _ctx, _call: clock.advance(1000))
    result = kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.ALLOW
    assert seen == [1]


def test_tool_replacement_after_authorisation_is_denied(signed_kernel):
    kernel, key, _clock, seen = signed_kernel

    def replace_tool(_ctx, _call):
        kernel._dispatcher.registry.unregister("probe")
        kernel._dispatcher.registry.register("probe", lambda amount: seen.append("replacement"))

    kernel.set_runtime_hooks(before_execute=replace_tool)
    result = kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.DENY
    assert "TOOL_BINDING_MISMATCH" in (result.error or "")
    assert seen == []


def test_unenforceable_permit_time_limit_does_not_run_handler(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    result = kernel.submit(
        request({"amount": 1}), signed_permit(key, {"amount": 1}, constraints={"max_time_ms": 1})
    )
    assert result.decision is Decision.DENY
    assert seen == []


def test_halted_instance_cannot_reboot_and_discard_evidence(signed_kernel):
    kernel, _key, _clock, _seen = signed_kernel
    kernel.submit(request({"amount": 1}))
    kernel.halt("test")
    before = kernel.export_evidence()
    with pytest.raises(BootError):
        kernel.boot(KernelConfig(AUDIENCE, "strict", clock=VirtualClock(1000)))
    assert kernel.get_state() is KernelState.HALTED
    assert kernel.export_evidence() == before


def test_malformed_wire_params_are_rejected(signed_kernel):
    kernel, _key, _clock, _seen = signed_kernel
    payload = {
        "request_id": "r",
        "actor": "agent",
        "intent": "local",
        "tool_call": {"name": "probe", "params": ["not", "a", "mapping"]},
    }
    with pytest.raises(ValueError):
        request_from_mapping(kernel, payload)


def test_foreign_evidence_label_is_rejected(signed_kernel):
    kernel, _key, _clock, _seen = signed_kernel
    ledger = AuditLedger("different", "strict")
    with pytest.raises(AuditError):
        kernel.load_ledger(ledger.export(1000))
    assert kernel.get_state() is KernelState.HALTED


@pytest.mark.parametrize("bind_constraints", [False, True])
def test_dual_channel_echo_authorises_and_audits_constraints(bind_constraints):
    key = Ed25519PrivateKey.generate()
    kernel = DualChannelKernel()
    kernel.boot(KernelConfig(AUDIENCE, "dual-channel", clock=VirtualClock(1000)))
    kernel.set_policy(
        JurisdictionPolicy(allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"echo"}))
    )
    kernel.set_public_verifiers(
        {KEY_ID: PublicVerificationKey("operator", AUDIENCE, key.public_key().public_bytes_raw())}
    )
    params = {
        "text": "hello",
        "constraints": {
            "scope": "echo",
            "non_goals": "other work",
            "success_criteria": "same text",
        },
    }
    unsigned = (
        PermitBuilder()
        .issuer("operator")
        .subject("agent")
        .jurisdiction("default")
        .action("echo")
        .params(params if bind_constraints else {"text": "hello"})
        .constraints({})
        .max_executions(1)
        .valid_from_ms(1)
        .valid_until_ms(2000)
        .proposal_hash("test-proposal")
        .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
    )
    permit = sign_v2_permit(unsigned, key)
    result = kernel.submit(
        KernelRequest("dual", 1000, "agent", "echo", ToolCall("echo", params), params), permit
    )
    if bind_constraints:
        assert result.decision is Decision.ALLOW
        assert result.tool_result == "hello"
        assert kernel.export_evidence().ledger_entries[0].params_hash == compute_hash_dict(params)
    else:
        assert result.decision is Decision.DENY
        assert result.tool_result is None


@pytest.mark.parametrize(
    "allow_intent_only, expected", [(False, Decision.DENY), (True, Decision.ALLOW)]
)
def test_intent_only_policy_is_enforced(allow_intent_only, expected):
    kernel = StrictKernel()
    kernel.boot(KernelConfig("policy", "strict", clock=VirtualClock(1000)))
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}),
            allowed_tools=frozenset({"echo"}),
            allow_intent_only=allow_intent_only,
        )
    )
    receipt = kernel.submit(KernelRequest("intent", 1000, "agent", "check policy"))
    assert receipt.decision is expected


def test_async_timeout_keeps_kernel_serialized_until_running_tool_finishes(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    started, release = Event(), Event()

    def slow_probe(amount=99):
        started.set()
        if not release.wait(5):
            raise RuntimeError("test timed out waiting for release")
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", slow_probe)
    wrapper = AsyncKernel(kernel)
    first_permit = signed_permit(key, {"amount": 1})
    second_permit = signed_permit(key, {"amount": 2})

    async def scenario():
        pending = asyncio.create_task(
            submit_with_timeout(
                wrapper, request({"amount": 1}, request_id="first"), 0.1, first_permit
            )
        )
        second = None
        try:
            assert await asyncio.to_thread(started.wait, 2)
            with pytest.raises(asyncio.TimeoutError):
                await pending
            second = asyncio.create_task(
                wrapper.submit(request({"amount": 2}, request_id="second"), second_permit)
            )
            await asyncio.sleep(0.05)
            assert not second.done(), "another request reached the still-running kernel"
        finally:
            release.set()
            if second is not None:
                result = await second
                assert result.decision is Decision.ALLOW
        assert seen == [1, 2]

    asyncio.run(scenario())


def test_concurrent_sync_submits_fail_fast_and_audit_every_request(signed_kernel):
    """SK-001: contention is denied without waiting on the executing handler."""
    from concurrent.futures import ThreadPoolExecutor

    kernel, key, _clock, seen = signed_kernel
    started, release = Event(), Event()

    def slow_probe(amount=99):
        started.set()
        if not release.wait(5):
            raise RuntimeError("test timed out waiting for release")
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", slow_probe)
    permit = signed_permit(key, {"amount": 1})

    def invoke(index):
        return kernel.submit(
            request({"amount": 1}, request_id=f"concurrent-{index}"), permit
        )

    with ThreadPoolExecutor(max_workers=32) as executor:
        first = executor.submit(invoke, 0)
        try:
            assert started.wait(timeout=2)
            others = [executor.submit(invoke, i) for i in range(1, 256)]
            # A full set of contenders responds while the first handler remains
            # active. An unbounded blocking lock fails this deterministic test.
            busy = [f.result(timeout=3) for f in others[:31]]
            assert all(x.decision is Decision.DENY for x in busy)
            assert all("KERNEL_BUSY" in (x.error or "") for x in busy)
        finally:
            release.set()
        results = [first.result(timeout=3)] + [f.result(timeout=3) for f in others]

    assert sum(x.decision is Decision.ALLOW for x in results) == 1
    assert sum(x.decision is Decision.DENY for x in results) == 255
    assert seen == [1]
    bundle = kernel.export_evidence()
    assert len(bundle.ledger_entries) == 257
    assert replay_and_verify(
        [audit_entry_to_dict(entry) for entry in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_nested_same_kernel_submit_is_denied_without_deadlock(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    nested = []

    def reentrant_probe(amount=99):
        nested.append(
            kernel.submit(
                request({"amount": 3}, request_id="nested"),
                signed_permit(key, {"amount": 3}),
            )
        )
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", reentrant_probe)
    result = kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
    assert result.decision is Decision.ALLOW
    assert len(nested) == 1
    assert nested[0].decision is Decision.DENY
    assert "KERNEL_BUSY" in (nested[0].error or "")
    assert seen == [1]


def test_concurrent_halt_preserves_completed_effect_outcome_audit(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    started, release = Event(), Event()
    result_holder = []

    def slow_probe(amount=99):
        started.set()
        if not release.wait(5):
            raise RuntimeError("test timed out waiting for release")
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", slow_probe)
    submitter = Thread(
        target=lambda: result_holder.append(
            kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
        ),
        daemon=True,
    )
    submitter.start()
    try:
        assert started.wait(timeout=2)
        queued = kernel.halt("emergency operator request")
        assert queued.decision is Decision.HALT
        assert queued.error == "HALT_QUEUED"
        assert kernel.get_state() is not KernelState.HALTED
    finally:
        release.set()
    submitter.join(timeout=3)
    assert not submitter.is_alive()
    assert len(result_holder) == 1
    assert result_holder[0].decision is Decision.ALLOW
    assert seen == [1]
    assert kernel.get_state() is KernelState.HALTED
    bundle = kernel.export_evidence()
    entries = [e for e in bundle.ledger_entries if e.request_id == "request"]
    assert any(e.audit_phase == "intent" for e in entries)
    assert any(e.audit_phase == "outcome" and e.decision is Decision.ALLOW for e in entries)
    assert any(e.error == "HALT_QUEUED" for e in bundle.ledger_entries)
    assert bundle.ledger_entries[-1].state_to is KernelState.HALTED
    assert replay_and_verify(
        [audit_entry_to_dict(entry) for entry in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_admission_helpers_reject_unbooted_kernel():
    kernel = StrictKernel()
    with pytest.raises(StateError, match="not booted"):
        kernel._deny_busy(request({"amount": 1}))
    with pytest.raises(StateError, match="not booted"):
        kernel._halt_locked("not booted")


def test_queued_halt_is_published_before_owner_unlocks(signed_kernel, monkeypatch):
    """An in-flight effect cannot be followed by a new admission during halt audit."""
    kernel, key, _clock, seen = signed_kernel
    started, release_handler = Event(), Event()
    queued_append_started, release_halt_audit = Event(), Event()
    submit_done = Event()
    receipts = []
    halted_receipts = []

    def slow_probe(amount=99):
        started.set()
        if not release_handler.wait(5):
            raise RuntimeError("handler release deadline exceeded")
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", slow_probe)
    ledger = kernel._ledger
    assert ledger is not None
    original_append = ledger.append

    def pause_halt_commit(*args, **kwargs):
        if kwargs.get("error") == "HALT_QUEUED":
            queued_append_started.set()
            if not release_halt_audit.wait(5):
                raise RuntimeError("halt audit release deadline exceeded")
        return original_append(*args, **kwargs)

    monkeypatch.setattr(ledger, "append", pause_halt_commit)

    def primary():
        try:
            receipts.append(
                kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
            )
        finally:
            submit_done.set()

    first = Thread(target=primary, daemon=True)
    halter = Thread(target=lambda: halted_receipts.append(kernel.halt("urgent")), daemon=True)
    first.start()
    try:
        assert started.wait(2)
        halter.start()
        assert queued_append_started.wait(2)
        release_handler.set()
        # The original request may write its outcome, but it must not release
        # admission ownership until the halt intent has been published.
        assert not submit_done.wait(0.15)
        concurrent = kernel.submit(
            request({"amount": 2}, request_id="after-halt-queued"),
            signed_permit(key, {"amount": 2}),
        )
        assert concurrent.decision is Decision.DENY
        assert "KERNEL_BUSY" in (concurrent.error or "")
    finally:
        release_handler.set()
        release_halt_audit.set()
        first.join(3)
        if halter.ident is not None:
            halter.join(3)
    assert not first.is_alive()
    assert not halter.is_alive()
    assert len(receipts) == 1
    assert receipts[0].decision is Decision.ALLOW
    assert len(halted_receipts) == 1
    assert halted_receipts[0].decision is Decision.HALT
    assert seen == [1]
    assert kernel.get_state() is KernelState.HALTED
    bundle = kernel.export_evidence()
    assert replay_and_verify(
        [audit_entry_to_dict(e) for e in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_queued_halt_finalizes_if_submit_releases_lock_during_audit(monkeypatch):
    """Force the narrow release-before-second-try-lock race deterministically."""
    kernel = StrictKernel()
    kernel.boot(KernelConfig("halt-race", "strict", clock=VirtualClock(1000)))
    ledger = kernel._ledger
    assert ledger is not None
    kernel._submit_lock.acquire()
    append_original = ledger.append

    def append_and_release(*args, **kwargs):
        result = append_original(*args, **kwargs)
        if kwargs.get("error") == "HALT_QUEUED":
            kernel._submit_lock.release()
        return result

    monkeypatch.setattr(ledger, "append", append_and_release)
    queued = kernel.halt("urgent")
    assert queued.error == "HALT_QUEUED"
    assert queued.decision is Decision.HALT
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None
    bundle = kernel.export_evidence()
    assert len(bundle.ledger_entries) == 2
    assert [e.error for e in bundle.ledger_entries] == ["HALT_QUEUED", None]
    assert replay_and_verify(
        [audit_entry_to_dict(e) for e in bundle.ledger_entries], bundle.root_hash
    )[0]


@pytest.mark.parametrize("failed_record", ["KERNEL_BUSY", "HALT_QUEUED"])
def test_failed_concurrent_admission_audit_quarantines_kernel(
    signed_kernel, monkeypatch, failed_record
):
    """A busy-denial or queued-halt audit write failure is a terminal fault."""
    kernel, key, _clock, seen = signed_kernel
    started, release = Event(), Event()
    completed = []

    def controlled_probe(amount=99):
        started.set()
        if not release.wait(5):
            raise RuntimeError("test timed out waiting for release")
        seen.append(amount)
        return amount

    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", controlled_probe)
    ledger = kernel._ledger
    assert ledger is not None
    original_append = ledger.append

    def fail_target_record(*args, **kwargs):
        if failed_record in (kwargs.get("error") or ""):
            raise AuditError("injected rejection audit failure")
        return original_append(*args, **kwargs)

    monkeypatch.setattr(ledger, "append", fail_target_record)
    worker = Thread(
        target=lambda: completed.append(
            kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
        ),
        daemon=True,
    )
    worker.start()
    try:
        assert started.wait(2)
        with pytest.raises(AuditError, match="injected rejection audit failure"):
            if failed_record == "KERNEL_BUSY":
                kernel.submit(request({"amount": 2}, request_id="busy"))
            else:
                kernel.halt("operator emergency")
        assert kernel._pending_halt is not None
    finally:
        release.set()
    worker.join(3)
    assert not worker.is_alive()
    assert len(completed) == 1
    assert completed[0].decision is Decision.ALLOW
    assert seen == [1]
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None
    bundle = kernel.export_evidence()
    assert bundle.ledger_entries[-1].state_to is KernelState.HALTED
    assert replay_and_verify(
        [audit_entry_to_dict(e) for e in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_audit_failure_quarantine_when_owner_already_released():
    """Lost audit while idle must halt immediately, not strand pending halt."""
    kernel = StrictKernel()
    kernel.boot(KernelConfig("unowned-audit", "strict", clock=VirtualClock(1000)))
    kernel._quarantine_failed_admission_audit("no audit persistence")
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None
    assert any(
        entry.decision is Decision.HALT for entry in kernel.export_evidence().ledger_entries
    )


def test_repeated_audit_quarantine_after_terminal_halt_is_idempotent():
    """An already halted instance never emits a second terminal audit entry."""
    kernel = StrictKernel()
    kernel.boot(KernelConfig("halted-quarantine", "strict", clock=VirtualClock(1000)))
    kernel.halt("original halt")
    before = kernel.export_evidence()
    kernel._quarantine_failed_admission_audit("late admission audit failure")
    after = kernel.export_evidence()
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None
    assert after.root_hash == before.root_hash
    assert len(after.ledger_entries) == len(before.ledger_entries)


def test_pending_halt_prevents_new_submission_even_before_terminal_transition():
    """The admission gate rejects a pending halt; subsequent finalization is terminal."""
    kernel = StrictKernel()
    kernel.boot(KernelConfig("pending-admission", "strict", clock=VirtualClock(1000)))
    kernel._pending_halt = "operator pending"
    refusal = kernel.submit(request({"amount": 1}))
    assert refusal.decision is Decision.DENY
    assert "KERNEL_BUSY" in (refusal.error or "")
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None


def test_audit_quarantine_is_not_stranded_at_submission_unlock(monkeypatch):
    """A failing audit cannot race the owner's final halt check and unlock."""
    from threading import Lock

    kernel = StrictKernel()
    kernel.boot(KernelConfig("unlock-race", "strict", clock=VirtualClock(1000)))
    entered_release, finish_release, quarantine_entered = Event(), Event(), Event()

    class PausingLock:
        def __init__(self):
            self.lock = Lock()
            self.paused = False

        def acquire(self, blocking=True):
            return self.lock.acquire(blocking=blocking)

        def release(self):
            if not self.paused:
                self.paused = True
                entered_release.set()
                if not finish_release.wait(3):
                    raise RuntimeError("Timed out at controlled admission unlock")
            self.lock.release()

    kernel._submit_lock = PausingLock()
    submit_outcome = []
    submitting = Thread(
        target=lambda: submit_outcome.append(kernel.submit(request({}))),
        daemon=True,
    )
    submitting.start()
    assert entered_release.wait(2)

    def quarantine():
        quarantine_entered.set()
        kernel._quarantine_failed_admission_audit("synthetic write failure")

    fault_thread = Thread(target=quarantine, daemon=True)
    fault_thread.start()
    try:
        assert quarantine_entered.wait(2)
        # While the first thread is in the final check/release critical section,
        # the quarantine writer must not finish and leave an IDLE pending halt.
        assert fault_thread.is_alive()
    finally:
        finish_release.set()
    submitting.join(3)
    fault_thread.join(3)
    assert not submitting.is_alive()
    assert not fault_thread.is_alive()
    assert len(submit_outcome) == 1
    assert kernel.get_state() is KernelState.HALTED
    assert kernel._pending_halt is None
    bundle = kernel.export_evidence()
    assert replay_and_verify(
        [audit_entry_to_dict(entry) for entry in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_queued_halt_skips_second_halt_after_racing_fault(monkeypatch):
    """Do not write a duplicate terminal event if the owner already halted."""
    kernel = StrictKernel()
    kernel.boot(KernelConfig("halt-fault-race", "strict", clock=VirtualClock(1000)))
    ledger = kernel._ledger
    assert ledger is not None
    kernel._submit_lock.acquire()
    original_append = ledger.append

    def append_and_fault(*args, **kwargs):
        entry = original_append(*args, **kwargs)
        if kwargs.get("error") == "HALT_QUEUED":
            kernel._submit_lock.release()
            kernel._halt_on_fault("synthetic racing terminal failure")
        return entry

    monkeypatch.setattr(ledger, "append", append_and_fault)
    queued = kernel.halt("requested")
    assert queued.decision is Decision.HALT
    assert queued.error == "HALT_QUEUED"
    assert kernel.get_state() is KernelState.HALTED
    bundle = kernel.export_evidence()
    assert len(bundle.ledger_entries) == 2
    assert [e.decision for e in bundle.ledger_entries] == [Decision.HALT, Decision.HALT]
    assert kernel._pending_halt is None
    assert replay_and_verify(
        [audit_entry_to_dict(entry) for entry in bundle.ledger_entries], bundle.root_hash
    )[0]


def test_sync_submit_releases_lock_after_fault_and_halts(signed_kernel, monkeypatch):
    """A failed submit cannot strand a lock or allow subsequent tool execution."""
    kernel, key, _clock, seen = signed_kernel

    def fail_after_admission(*_args):
        raise RuntimeError("injected processing fault")

    monkeypatch.setattr(kernel, "_submit_bound", fail_after_admission)
    with pytest.raises(RuntimeError, match="injected processing fault"):
        kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
    assert kernel.get_state() is KernelState.HALTED
    assert seen == []

    # A different thread must immediately recover ownership of the admission lock
    # and observe the terminal halted state, never hang on the first caller.
    done = Event()
    observed = []

    def subsequent_submit():
        try:
            kernel.submit(request({"amount": 1}), signed_permit(key, {"amount": 1}))
        except StateError as exc:
            observed.append(str(exc))
        finally:
            done.set()

    thread = Thread(target=subsequent_submit, daemon=True)
    thread.start()
    assert done.wait(timeout=2), "submit lock was leaked after handler exception"
    thread.join(timeout=1)
    assert observed and "halted" in observed[0].lower()
    assert seen == []


def test_async_batch_rejects_mismatched_permit_count_without_submitting():
    class FakeKernel:
        def __init__(self):
            self.seen = []

        async def submit(self, req, permit):
            self.seen.append(req.request_id)

    async def scenario():
        kernel = FakeKernel()
        with pytest.raises(ValueError, match="permit"):
            await submit_batch(kernel, [request({}), request({})], [None])
        assert kernel.seen == []

    asyncio.run(scenario())


def test_async_retry_rejects_negative_retry_count():
    async def scenario():
        with pytest.raises(ValueError, match="max_retries"):
            await submit_with_retry(object(), request({}), max_retries=-1)

    asyncio.run(scenario())


def test_evidence_export_waits_for_atomic_hash_chain_append():
    ledger = AuditLedger("concurrent", "strict")
    appended, release = Event(), Event()
    snapshots = {}
    finished = {name: Event() for name in ("export", "entries", "root_hash", "length")}

    class PausingEntries(list):
        def append(self, entry):
            super().append(entry)
            appended.set()
            if not release.wait(5):
                raise RuntimeError("test timed out waiting for release")

    ledger._entries = PausingEntries()
    worker = Thread(
        target=lambda: ledger.append(
            request_id="r",
            actor="agent",
            intent="test",
            decision=Decision.DENY,
            state_from=KernelState.IDLE,
            state_to=KernelState.COMPLETED,
            ts_ms=1000,
        ),
        daemon=True,
    )

    def snapshot(name, getter):
        snapshots[name] = getter()
        finished[name].set()

    getters = {
        "export": lambda: ledger.export(1000),
        "entries": lambda: ledger.entries,
        "root_hash": lambda: ledger.root_hash,
        "length": lambda: ledger.length,
    }
    readers = [
        Thread(target=snapshot, args=(name, getter), daemon=True)
        for name, getter in getters.items()
    ]
    worker.start()
    try:
        assert appended.wait(2)
        for reader in readers:
            reader.start()
        # No snapshot can observe _entries before its hash-chain head commits.
        assert all(not done.wait(0.05) for done in finished.values())
    finally:
        release.set()
        worker.join(2)
        for reader in readers:
            if reader.ident is not None:
                reader.join(2)
    assert not worker.is_alive()
    assert all(not reader.is_alive() for reader in readers)
    assert all(done.is_set() for done in finished.values())
    bundle = snapshots["export"]
    assert snapshots["entries"] == bundle.ledger_entries
    assert snapshots["root_hash"] == bundle.root_hash
    assert snapshots["length"] == len(bundle.ledger_entries) == 1
    payload = {
        "ledger_entries": [audit_entry_to_dict(entry) for entry in bundle.ledger_entries],
        "root_hash": bundle.root_hash,
    }
    assert verify_evidence_bundle(payload).is_valid


def test_cancelled_async_halt_keeps_other_operations_serialized():
    started, release, submitted = Event(), Event(), Event()

    class BlockingKernel:
        def halt(self, reason):
            started.set()
            if not release.wait(5):
                raise RuntimeError("test timed out waiting for release")
            return reason

        def submit(self, req, permit):
            submitted.set()
            return "submitted"

    async def scenario():
        wrapper = AsyncKernel(BlockingKernel())
        stopping = asyncio.create_task(wrapper.halt("halt"))
        pending = None
        try:
            assert await asyncio.to_thread(started.wait, 2)
            stopping.cancel()
            with pytest.raises(asyncio.CancelledError):
                await stopping
            pending = asyncio.create_task(wrapper.submit(request({})))
            await asyncio.sleep(0.05)
            assert not submitted.is_set()
        finally:
            release.set()
            if pending is not None:
                assert await pending == "submitted"

    asyncio.run(scenario())


def test_async_wrapper_can_be_reused_after_its_event_loop_has_closed():
    from shards_kernel.async_support.async_kernel import AsyncStrictKernel

    kernel = AsyncStrictKernel("multiple-loops")
    first = asyncio.run(kernel.submit(KernelRequest("first", 0, "agent", "inspect")))
    second = asyncio.run(kernel.submit(KernelRequest("second", 0, "agent", "inspect")))
    assert first.decision is Decision.ALLOW
    assert second.decision is Decision.ALLOW


def test_async_wrapper_refuses_two_active_event_loops():
    started, release = Event(), Event()
    outcomes = []

    class BlockingKernel:
        def submit(self, req, permit):
            started.set()
            if not release.wait(5):
                raise RuntimeError("test timed out waiting for release")
            return "done"

    wrapper = AsyncKernel(BlockingKernel())
    worker = Thread(target=lambda: outcomes.append(asyncio.run(wrapper.submit(request({})))))
    worker.start()
    try:
        assert started.wait(2)
        with pytest.raises(StateError, match="active event loops"):
            asyncio.run(wrapper.submit(request({})))
    finally:
        release.set()
        worker.join(2)
    assert outcomes == ["done"]


@pytest.mark.parametrize("value", [True, False, 0, -1, "10", 1.5, None])
def test_malformed_time_limits_are_rejected_before_execution(signed_kernel, value):
    kernel, key, _clock, seen = signed_kernel
    receipt = kernel.submit(
        request({"amount": 1}),
        signed_permit(key, {"amount": 1}, constraints={"max_time_ms": value}),
    )
    assert receipt.decision is Decision.DENY
    assert "CONSTRAINT_MALFORMED_MAX_TIME_MS" in (receipt.error or "")
    assert seen == []


def test_missing_required_handler_argument_denied_before_execution(signed_kernel):
    kernel, key, _clock, seen = signed_kernel
    kernel._dispatcher.registry.unregister("probe")
    kernel._dispatcher.registry.register("probe", lambda amount: seen.append(amount))
    receipt = kernel.submit(request({}), signed_permit(key, {}))
    assert receipt.decision is Decision.DENY
    assert "PARAM_BINDING_MISMATCH" in (receipt.error or "")
    assert seen == []
    assert all(entry.audit_phase != "intent" for entry in kernel.export_evidence().ledger_entries)


def test_json_authorisation_comparison_fail_closed_for_non_json_values():
    from shards_kernel.common.codec import equal_json_values

    assert equal_json_values({"items": [1, {"enabled": True}]}, {"items": [1, {"enabled": True}]})
    assert not equal_json_values({"value": True}, {"value": 1})
    assert not equal_json_values(-0.0, 0.0)
    assert not equal_json_values(float("nan"), float("nan"))
    assert not equal_json_values(float("inf"), float("inf"))
    assert not equal_json_values({1: "value"}, {1: "value"})
    assert not equal_json_values((1,), (1,))
    cycle = []
    cycle.append(cycle)
    assert not equal_json_values(cycle, cycle)


def test_dual_channel_split_keeps_context_without_leaking_tool_kwargs():
    kernel = DualChannelKernel()
    params = {"text": "hello", "constraints": {"scope": "echo"}}

    def plain(text):
        return text

    def explicit(text, *, constraints):
        return text, constraints

    def variadic(text, **kwargs):
        return text, kwargs

    assert kernel._split_dispatch_params({"text": "hello"}, plain) == ({"text": "hello"}, {})
    assert kernel._split_dispatch_params(params, plain) == (
        {"text": "hello"}, {"constraints": {"scope": "echo"}}
    )
    assert kernel._split_dispatch_params(params, explicit) == (params, {})
    assert kernel._split_dispatch_params(params, variadic) == (params, {})
    # A signature that cannot be inspected remains intact; the later
    # effective-argument binder rejects it before any execution.
    assert kernel._split_dispatch_params(params, object()) == (params, {})
