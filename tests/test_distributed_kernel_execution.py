"""Bounded end-to-end strict-kernel integration with global PostgreSQL budget.

Tests use real PostgreSQL only where a disposable SHARDS_TEST_POSTGRES_DSN is
provided. Local-only validation tests run in the default Python matrix.
This intentionally does not expose remote or provider-effect tools.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.common.errors import StateError
from shards_kernel.common.types import (
    Decision, KernelConfig, KernelRequest, KernelState, ToolCall, VirtualClock,
)
from shards_kernel.distributed.postgres import PostgresPermitJournal
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey
from shards_kernel.variants.strict_kernel import StrictKernel

AUDIENCE = "shared-operator"
KEY_ID = "external-key"


def make_kernel(journal, public_key):
    kernel = StrictKernel()
    kernel.enable_shared_permit_accounting(journal)
    kernel.boot(KernelConfig(
        kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)
    ))
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}),
        allowed_tools=frozenset({"echo"}),
    ))
    kernel.set_public_verifiers({KEY_ID: PublicVerificationKey(
        issuer="operator", audience=AUDIENCE, public_key=public_key
    )})
    return kernel


def signed_permit(private_key):
    token = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("echo")
        .params({"text": "approved"}).constraints({})
        .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("approved-proposal")
        .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
    )
    return sign_v2_permit(token, private_key)


def request(request_id):
    return KernelRequest(
        request_id=request_id, ts_ms=1000, actor="alice",
        intent="echo approved text",
        tool_call=ToolCall(name="echo", params={"text": "approved"}),
        params={"text": "approved"},
    )


@pytest.fixture
def signing():
    secret = Ed25519PrivateKey.generate()
    return secret, secret.public_key().public_bytes_raw()


@pytest.fixture
def postgres_journal():
    if not os.environ.get("SHARDS_TEST_POSTGRES_DSN"):
        pytest.skip("Real PostgreSQL is required for distributed execution tests")
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    journal = PostgresPermitJournal(lambda: psycopg.connect(dsn, connect_timeout=5))
    journal.initialize_schema()
    return journal


def test_enable_is_explicit_preboot_and_requires_postgres(signing):
    secret, public = signing
    kernel = StrictKernel()
    with pytest.raises(TypeError, match="PostgresPermitJournal"):
        kernel.enable_shared_permit_accounting(object())
    journal = PostgresPermitJournal(lambda: None)
    kernel.enable_shared_permit_accounting(journal)
    kernel.boot(KernelConfig(
        kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)
    ))
    with pytest.raises(StateError, match="before boot"):
        kernel.enable_shared_permit_accounting(journal)
    assert kernel._shared_permit_journal is journal


def test_single_global_permit_cannot_execute_on_two_kernels(postgres_journal, signing):
    secret, public = signing
    permit = signed_permit(secret)
    a = make_kernel(postgres_journal, public)
    b = make_kernel(postgres_journal, public)
    first = a.submit(request(uuid4().hex), permit_token=permit)
    assert first.decision is Decision.ALLOW
    assert first.tool_result == "approved"
    assert any(e.audit_phase == "intent" for e in a.export_evidence().ledger_entries)
    denied = b.submit(request(uuid4().hex), permit_token=permit)
    assert denied.decision is Decision.DENY
    assert denied.tool_result is None
    assert "GLOBAL_PERMIT_EXHAUSTED" in (denied.error or "")
    assert not [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]


def test_bad_signature_denied_before_budget_consumption(postgres_journal, signing):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    attacker = Ed25519PrivateKey.generate()
    good = signed_permit(secret)
    # Tampering with the valid token's signature retains the same nonce.
    from dataclasses import replace
    permit = replace(good, signature=sign_v2_permit(
        replace(good, signature=""), attacker
    ).signature)
    denied = kernel.submit(request(uuid4().hex), permit_token=permit)
    assert denied.decision is Decision.DENY
    assert "SIGNATURE_INVALID" in (denied.error or "")
    assert not [x for x in postgres_journal.unresolved() if x.permit_id == good.permit_id]
    # The original valid signed permit and nonce remain spendable.
    assert kernel.submit(request(uuid4().hex), permit_token=good).decision is Decision.ALLOW


def test_tool_registry_substitution_denied_before_reservation(postgres_journal, signing):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)
    executed = []
    kernel._dispatcher.registry.unregister("echo")
    kernel._dispatcher.registry.register("echo", lambda text: executed.append(text))
    result = kernel.submit(request(uuid4().hex), permit_token=permit)
    assert result.decision is Decision.DENY
    assert "DISTRIBUTED_TOOL_NOT_APPROVED" in (result.error or "")
    assert executed == []
    assert not [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]


def test_primary_outage_halts_before_dispatch(signing):
    secret, public = signing
    bad_journal = PostgresPermitJournal(
        lambda: (_ for _ in ()).throw(ConnectionError("primary offline"))
    )
    kernel = make_kernel(bad_journal, public)
    with pytest.raises(ConnectionError, match="primary offline"):
        kernel.submit(request(uuid4().hex), permit_token=signed_permit(secret))
    assert kernel.get_state() is KernelState.HALTED


def test_crash_after_global_reservation_before_local_intent_stays_reserved(
    postgres_journal, signing, monkeypatch
):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    operation_request = request(uuid4().hex)
    permit = signed_permit(secret)

    def fail_local_append(**kwargs):
        raise OSError("local audit filesystem unavailable")

    monkeypatch.setattr(kernel._ledger, "append", fail_local_append)
    with pytest.raises(OSError, match="filesystem unavailable"):
        kernel.submit(operation_request, permit_token=permit)
    assert kernel.get_state() is KernelState.HALTED
    reserved = [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]
    assert len(reserved) == 1 and reserved[0].state == "RESERVED"
    # Even a different fresh host cannot spend the same single-use permit.
    retry = make_kernel(postgres_journal, public)
    denied = retry.submit(request(uuid4().hex), permit_token=permit)
    assert denied.decision is Decision.DENY


def test_uncertain_execution_is_not_retried_automatically(
    postgres_journal, signing, monkeypatch
):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)

    def lose_execution_reply(*args, **kwargs):
        raise RuntimeError("execution acknowledgement lost")

    monkeypatch.setattr(kernel._runtime, "execute", lose_execution_reply)
    with pytest.raises(RuntimeError, match="acknowledgement lost"):
        kernel.submit(request(uuid4().hex), permit_token=permit)
    assert kernel.get_state() is KernelState.HALTED
    outstanding = [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]
    assert len(outstanding) == 1 and outstanding[0].state == "DISPATCHED"
    retry = make_kernel(postgres_journal, public)
    assert retry.submit(request(uuid4().hex), permit_token=permit).decision is Decision.DENY


def test_shared_primary_is_only_nonce_authority(postgres_journal, signing):
    """Out-of-sync local replay projection cannot reject after global spend."""
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)
    # Simulate an older local ledger that cached a use which is not present
    # in the shared database. The shared primary is authoritative here.
    assert kernel._nonce_registry.check_and_record(
        nonce=permit.nonce, issuer=permit.issuer, subject=permit.subject,
        permit_id=permit.permit_id, max_executions=permit.max_executions,
        current_time_ms=1000,
    )
    op_req = request(uuid4().hex)
    first = kernel.submit(op_req, permit_token=permit)
    assert first.decision is Decision.ALLOW
    from shards_kernel.common.hashing import compute_hash_dict
    op_id = compute_hash_dict({
        "domain": "SHARDS-SHARED-OPERATION-V1",
        "kernel_id": AUDIENCE,
        "actor": op_req.actor,
        "request_id": op_req.request_id,
    })
    completed = postgres_journal.get(op_id)
    assert completed is not None and completed.state == "SUCCEEDED"
    assert completed.evidence_ref == kernel.export_evidence().ledger_entries[-1].entry_hash
    assert completed.provider_ref == "builtin:" + op_id
    # Any reuse remains denied by PostgreSQL, even with a fresh request ID.
    second = make_kernel(postgres_journal, public)
    denied = second.submit(request(uuid4().hex), permit_token=permit)
    assert denied.decision is Decision.DENY


def test_shared_mode_refuses_insecure_or_non_strict_boot(signing):
    from shards_kernel.common.errors import BootError
    from shards_kernel.variants.permissive_kernel import PermissiveKernel

    journal = PostgresPermitJournal(lambda: None)
    permissive = PermissiveKernel()
    permissive.enable_shared_permit_accounting(journal)
    with pytest.raises(BootError, match="strict"):
        permissive.boot(KernelConfig(
            kernel_id=AUDIENCE, variant="permissive", clock=VirtualClock(1000)
        ))
    strict = StrictKernel()
    strict.enable_shared_permit_accounting(journal)
    with pytest.raises(BootError, match="insecure"):
        strict.boot(KernelConfig(
            kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000),
            allow_insecure_unpermitted_execution=True,
        ))


def test_existing_local_hmac_replay_semantics_unchanged():
    kernel = StrictKernel()
    kernel.boot(KernelConfig(
        kernel_id="local-test", variant="strict", clock=VirtualClock(1000)
    ))
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}),
        allowed_tools=frozenset({"echo"}),
    ))
    keyring = {"local-key": b"only-for-test-with-32-byte-key--"}
    kernel.set_keyring(keyring)
    signed = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("echo")
        .params({"text": "approved"}).constraints({})
        .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("local-test")
        .build(keyring, "local-key")
    )
    assert kernel.submit(request("local-first"), permit_token=signed).decision is Decision.ALLOW
    assert kernel.submit(request("local-second"), permit_token=signed).decision is Decision.DENY


def test_builtin_add_reconciles_with_audit_hash(postgres_journal, signing):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}),
        allowed_tools=frozenset({"add"}),
    ))
    signed = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("add")
        .params({"a": 2, "b": 3}).constraints({})
        .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("approved-add")
        .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
    )
    permit = sign_v2_permit(signed, secret)
    op_req = KernelRequest(
        request_id=uuid4().hex, ts_ms=1000, actor="alice",
        intent="add approved integers",
        tool_call=ToolCall(name="add", params={"a": 2, "b": 3}),
        params={"a": 2, "b": 3},
    )
    response = kernel.submit(op_req, permit_token=permit)
    assert response.decision is Decision.ALLOW
    assert response.tool_result == 5
    from shards_kernel.common.hashing import compute_hash_dict
    op_id = compute_hash_dict({
        "domain": "SHARDS-SHARED-OPERATION-V1",
        "kernel_id": AUDIENCE,
        "actor": op_req.actor,
        "request_id": op_req.request_id,
    })
    entry = postgres_journal.get(op_id)
    assert entry is not None and entry.state == "SUCCEEDED"
    assert entry.evidence_ref == response.evidence_hash


def test_rejected_legacy_hmac_never_reserves_global_budget(postgres_journal):
    kernel = StrictKernel()
    kernel.enable_shared_permit_accounting(postgres_journal)
    kernel.boot(KernelConfig(kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)))
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}), allowed_tools=frozenset({"echo"})
    ))
    keyring = {"legacy-key": b"test-only-32-byte-local-secret--"}
    kernel.set_keyring(keyring)
    permit = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("echo").params({"text": "approved"})
        .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("legacy-in-shared").build(keyring, "legacy-key")
    )
    result = kernel.submit(request(uuid4().hex), permit_token=permit)
    assert result.decision is Decision.DENY
    assert "DISTRIBUTED_REQUIRES_ED25519" in (result.error or "")
    assert not [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]


def test_only_pinned_builtins_can_reach_global_reservation(postgres_journal, signing):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}), allowed_tools=frozenset({"not-installed"})
    ))
    unsigned = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("not-installed")
        .params({}).constraints({}).max_executions(1)
        .valid_from_ms(0).valid_until_ms(2000).proposal_hash("not-installed")
        .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
    )
    permit = sign_v2_permit(unsigned, secret)
    req = KernelRequest(
        request_id=uuid4().hex, ts_ms=1000, actor="alice",
        intent="invoke unregistered tool",
        tool_call=ToolCall(name="not-installed", params={}), params={},
    )
    response = kernel.submit(req, permit_token=permit)
    assert response.decision is Decision.DENY
    assert "DISTRIBUTED_TOOL_NOT_APPROVED" in (response.error or "")
    assert not [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]


def test_dispatch_gate_failure_halts_before_tool_effect(postgres_journal, signing, monkeypatch):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)
    # Simulate a failing/blocked durable DISPATCHED state transition.
    monkeypatch.setattr(postgres_journal, "mark_dispatched", lambda _: False)
    with pytest.raises(Exception, match="dispatch gate refused"):
        kernel.submit(request(uuid4().hex), permit_token=permit)
    assert kernel.get_state() is KernelState.HALTED
    reserved = [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]
    assert len(reserved) == 1 and reserved[0].state == "RESERVED"


def test_failed_builtin_execution_quarantines_unknown(
    postgres_journal, signing, monkeypatch
):
    from types import SimpleNamespace
    from shards_kernel.common.types import ReceiptStatus

    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)
    failed = SimpleNamespace(
        dispatcher_result=SimpleNamespace(success=False, error="ambiguous fault")
    )
    monkeypatch.setattr(kernel._runtime, "execute", lambda *args, **kwargs: failed)
    response = kernel.submit(request(uuid4().hex), permit_token=permit)
    assert response.status is ReceiptStatus.FAILED
    outstanding = [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]
    assert len(outstanding) == 1 and outstanding[0].state == "UNKNOWN"


def test_failed_reconciliation_halts_without_releasing_budget(
    postgres_journal, signing, monkeypatch
):
    secret, public = signing
    kernel = make_kernel(postgres_journal, public)
    permit = signed_permit(secret)
    monkeypatch.setattr(postgres_journal, "reconcile", lambda *args, **kwargs: False)
    with pytest.raises(Exception, match="reconcile committed builtin"):
        kernel.submit(request(uuid4().hex), permit_token=permit)
    assert kernel.get_state() is KernelState.HALTED
    outstanding = [x for x in postgres_journal.unresolved() if x.permit_id == permit.permit_id]
    assert len(outstanding) == 1 and outstanding[0].state == "DISPATCHED"
    second = make_kernel(postgres_journal, public)
    assert second.submit(request(uuid4().hex), permit_token=permit).decision is Decision.DENY


def test_global_strict_admission_boundary_without_database_is_unit_testable(
    signing, monkeypatch
):
    """Exercise code-path coverage in every Python CI version.

    Real PostgreSQL concurrency and persistence tests remain in the dedicated
    acceptance job; this fake is NOT evidence of distributed correctness.
    """
    secret, public = signing
    journal = PostgresPermitJournal(lambda: None)
    calls = []
    monkeypatch.setattr(journal, "reserve", lambda **kwargs: calls.append(("reserve", kwargs)) or True)
    monkeypatch.setattr(journal, "mark_dispatched", lambda op: calls.append(("dispatch", op)) or True)
    monkeypatch.setattr(
        journal, "reconcile",
        lambda op, **kwargs: calls.append(("reconcile", (op, kwargs))) or True,
    )
    kernel = make_kernel(journal, public)
    receipt = kernel.submit(request("unit-shared-success"), permit_token=signed_permit(secret))
    assert receipt.decision is Decision.ALLOW and receipt.tool_result == "approved"
    assert [x[0] for x in calls] == ["reserve", "dispatch", "reconcile"]
    assert calls[0][1]["request_sha256"]
    assert calls[2][1][1]["evidence_ref"] == receipt.evidence_hash


def test_global_strict_budget_denial_is_pre_execution(signing, monkeypatch):
    secret, public = signing
    journal = PostgresPermitJournal(lambda: None)
    monkeypatch.setattr(journal, "reserve", lambda **kwargs: False)
    kernel = make_kernel(journal, public)
    receipt = kernel.submit(request("unit-exhausted"), permit_token=signed_permit(secret))
    assert receipt.decision is Decision.DENY
    assert "GLOBAL_PERMIT_EXHAUSTED" in (receipt.error or "")
    assert receipt.tool_result is None


def test_global_strict_requires_pinned_ed25519_not_legacy_hmac(signing):
    journal = PostgresPermitJournal(lambda: None)
    kernel = StrictKernel()
    kernel.enable_shared_permit_accounting(journal)
    kernel.boot(KernelConfig(kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)))
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"alice"}), allowed_tools=frozenset({"echo"})
    ))
    keyring = {"legacy": b"test-hmac-key-for-local-tests-32x"}
    kernel.set_keyring(keyring)
    permit = (
        PermitBuilder().issuer("operator").subject("alice")
        .jurisdiction("default").action("echo").params({"text": "approved"})
        .max_executions(1).valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("reject-hmac").build(keyring, "legacy")
    )
    receipt = kernel.submit(request("unit-reject-hmac"), permit_token=permit)
    assert receipt.decision is Decision.DENY
    assert "DISTRIBUTED_REQUIRES_ED25519" in (receipt.error or "")


def test_global_strict_refuses_registry_substitution_with_unit_journal(
    signing, monkeypatch
):
    secret, public = signing
    journal = PostgresPermitJournal(lambda: None)
    monkeypatch.setattr(journal, "reserve", lambda **kwargs: pytest.fail("unapproved reserve"))
    kernel = make_kernel(journal, public)
    kernel._dispatcher.registry.unregister("echo")
    kernel._dispatcher.registry.register("echo", lambda text: "forged")
    receipt = kernel.submit(request("unit-tool-swap"), permit_token=signed_permit(secret))
    assert receipt.decision is Decision.DENY
    assert "DISTRIBUTED_TOOL_NOT_APPROVED" in (receipt.error or "")


def test_global_strict_dispatch_and_reconcile_faults_halt_with_unit_journal(
    signing, monkeypatch
):
    secret, public = signing
    for fault in ("dispatch", "reconcile"):
        journal = PostgresPermitJournal(lambda: None)
        monkeypatch.setattr(journal, "reserve", lambda **kwargs: True)
        monkeypatch.setattr(journal, "mark_dispatched", lambda op: fault != "dispatch")
        monkeypatch.setattr(
            journal, "reconcile", lambda *args, **kwargs: fault != "reconcile"
        )
        kernel = make_kernel(journal, public)
        with pytest.raises(Exception, match="gate refused|reconcile committed builtin"):
            kernel.submit(request("unit-" + fault), permit_token=signed_permit(secret))
        assert kernel.get_state() is KernelState.HALTED


def test_global_strict_runtime_failure_marks_unknown_in_unit_journal(
    signing, monkeypatch
):
    from types import SimpleNamespace
    secret, public = signing
    journal = PostgresPermitJournal(lambda: None)
    calls = []
    monkeypatch.setattr(journal, "reserve", lambda **kwargs: True)
    monkeypatch.setattr(journal, "mark_dispatched", lambda op: True)
    monkeypatch.setattr(journal, "mark_unknown", lambda op: calls.append(op) or True)
    kernel = make_kernel(journal, public)
    fake_failure = SimpleNamespace(
        dispatcher_result=SimpleNamespace(success=False, error="network uncertain")
    )
    monkeypatch.setattr(kernel._runtime, "execute", lambda *args, **kwargs: fake_failure)
    result = kernel.submit(request("unit-runtime-error"), permit_token=signed_permit(secret))
    assert result.decision is Decision.DENY
    assert len(calls) == 1


def test_global_strict_failed_unknown_transition_halts(
    signing, monkeypatch
):
    from types import SimpleNamespace
    secret, public = signing
    journal = PostgresPermitJournal(lambda: None)
    monkeypatch.setattr(journal, "reserve", lambda **kwargs: True)
    monkeypatch.setattr(journal, "mark_dispatched", lambda op: True)
    monkeypatch.setattr(journal, "mark_unknown", lambda op: False)
    kernel = make_kernel(journal, public)
    fake_failure = SimpleNamespace(
        dispatcher_result=SimpleNamespace(success=False, error="network uncertain")
    )
    monkeypatch.setattr(kernel._runtime, "execute", lambda *args, **kwargs: fake_failure)
    with pytest.raises(Exception, match="mark failed operation UNKNOWN"):
        kernel.submit(request("unit-failed-unknown"), permit_token=signed_permit(secret))
    assert kernel.get_state() is KernelState.HALTED
