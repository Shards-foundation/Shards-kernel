"""Real PostgreSQL acceptance tests for cross-host permit accounting.

Executed with SHARDS_TEST_POSTGRES_DSN and a disposable PostgreSQL service.
Other test jobs skip rather than claiming distributed coverage.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from shards_kernel.distributed.postgres import PermitAccountingError, PostgresPermitJournal

pytestmark = pytest.mark.skipif(
    not os.environ.get("SHARDS_TEST_POSTGRES_DSN"),
    reason="Real PostgreSQL is required for distributed accounting acceptance",
)


@pytest.fixture
def journal():
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    store = PostgresPermitJournal(lambda: psycopg.connect(dsn, connect_timeout=5))
    store.initialize_schema()
    return store


def permit(max_executions=1):
    return {
        "permit_id": uuid4().hex,
        "issuer": "issuer-a",
        "subject": "agent-a",
        "nonce": uuid4().hex,
        "max_executions": max_executions,
        "request_sha256": "a" * 64,
    }


def reserve(store, p, operation_id=None):
    return store.reserve(operation_id=operation_id if operation_id is not None else uuid4().hex, **p)


def test_single_use_and_no_tentative_intent_left_on_denial(journal):
    p = permit()
    op1, op2 = uuid4().hex, uuid4().hex
    assert reserve(journal, p, op1)
    assert not reserve(journal, p, op1)
    assert not reserve(journal, p, op2)
    assert journal.get(op1).state == "RESERVED"
    assert journal.get(op2) is None


def test_distinct_hosts_compete_for_one_global_use(journal):
    p = permit()
    # Each journal instance uses a fresh independent PostgreSQL connection.
    second = PostgresPermitJournal(journal._connect)
    with ThreadPoolExecutor(max_workers=12) as workers:
        results = list(
            workers.map(
                lambda i: reserve(journal if i % 2 else second, p),
                range(32),
            )
        )
    assert sum(results) == 1


def test_multi_use_budget_and_same_operation_never_double_charges(journal):
    p = permit(max_executions=2)
    op = uuid4().hex
    assert reserve(journal, p, op)
    assert not reserve(journal, p, op)
    assert reserve(journal, p)
    assert not reserve(journal, p)


def test_nonce_collision_is_fail_closed_and_not_spent(journal):
    p = permit(max_executions=3)
    assert reserve(journal, p)
    forged = {**p, "permit_id": uuid4().hex}
    with pytest.raises(PermitAccountingError, match="Nonce is bound"):
        reserve(journal, forged)
    assert reserve(journal, p)
    assert reserve(journal, p)
    assert not reserve(journal, p)


def test_ambiguous_external_effect_requires_reconciliation(journal):
    p = permit()
    op = uuid4().hex
    assert reserve(journal, p, op)
    assert journal.mark_dispatched(op)
    assert not journal.mark_dispatched(op)
    assert journal.mark_unknown(op)
    assert not journal.mark_dispatched(op)
    assert journal.get(op).state == "UNKNOWN"
    assert any(item.operation_id == op for item in journal.unresolved())
    with pytest.raises(ValueError, match="Only verified"):
        journal.reconcile(op, outcome="FAILED", evidence_ref="proof")
    with pytest.raises(ValueError, match="provider_ref"):
        journal.reconcile(op, outcome="SUCCEEDED", evidence_ref="proof")
    assert journal.reconcile(
        op, outcome="SUCCEEDED", evidence_ref="evidence:verified", provider_ref="provider:123"
    )
    assert not journal.reconcile(
        op, outcome="SUCCEEDED", evidence_ref="evidence:verified", provider_ref="provider:123"
    )
    assert journal.get(op).provider_ref == "provider:123"
    assert all(item.operation_id != op for item in journal.unresolved())


def test_reserved_does_not_claim_external_success(journal):
    p = permit()
    op = uuid4().hex
    assert reserve(journal, p, op)
    assert not journal.mark_unknown(op)
    assert not journal.reconcile(
        op, outcome="NOT_APPLIED", evidence_ref="provider:proof-of-absence"
    )
    assert journal.mark_dispatched(op)
    assert journal.reconcile(
        op, outcome="NOT_APPLIED", evidence_ref="provider:proof-of-absence"
    )
    assert not journal.mark_dispatched(op)


def test_partition_and_validation_fail_closed(journal):
    p = permit()
    broken = PostgresPermitJournal(lambda: (_ for _ in ()).throw(OSError("primary offline")))
    with pytest.raises(OSError, match="primary offline"):
        reserve(broken, p)
    assert journal.get(uuid4().hex) is None
    with pytest.raises(ValueError, match="request_sha256"):
        reserve(journal, {**p, "request_sha256": "not-a-hash"})
    with pytest.raises(ValueError, match="max_executions"):
        reserve(journal, {**p, "max_executions": True})
    with pytest.raises(ValueError, match="limit"):
        journal.unresolved(limit=0)


def test_identifier_and_public_api_input_boundaries(journal):
    p = permit()
    invalid_ids = ("", " ", "a b", chr(10), "nonascii-λ", "x" * 257)
    for bad in invalid_ids:
        with pytest.raises(ValueError):
            reserve(journal, p, operation_id=bad)
        with pytest.raises(ValueError):
            journal.get(bad)
        with pytest.raises(ValueError):
            journal.mark_dispatched(bad)
        with pytest.raises(ValueError):
            journal.mark_unknown(bad)

    for field in ("issuer", "subject", "permit_id", "nonce"):
        with pytest.raises(ValueError):
            reserve(journal, {**p, field: ""})
    with pytest.raises(ValueError):
        journal.unresolved(limit=True)
    with pytest.raises(ValueError):
        journal.unresolved(limit=1001)
    with pytest.raises(ValueError):
        journal.reconcile("op", outcome="UNKNOWN", evidence_ref="proof")
    with pytest.raises(ValueError):
        journal.reconcile("op", outcome="SUCCEEDED", evidence_ref="proof", provider_ref="")
    with pytest.raises(ValueError):
        journal.reconcile("op", outcome="NOT_APPLIED", evidence_ref="")

    
def test_all_recovery_operations_fail_closed_when_primary_unreachable():
    def offline():
        raise ConnectionError("primary offline")

    journal = PostgresPermitJournal(offline)
    for operation in (
        lambda: journal.mark_dispatched("op"),
        lambda: journal.mark_unknown("op"),
        lambda: journal.reconcile("op", outcome="NOT_APPLIED", evidence_ref="proof"),
        lambda: journal.get("op"),
        lambda: journal.unresolved(),
    ):
        with pytest.raises(ConnectionError, match="primary offline"):
            operation()
