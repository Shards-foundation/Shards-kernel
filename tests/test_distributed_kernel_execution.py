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
