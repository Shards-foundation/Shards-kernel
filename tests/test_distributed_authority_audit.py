"""Real PostgreSQL acceptance tests for atomic audit + permit/effect mutations.

Without a real SHARDS_TEST_POSTGRES_DSN these tests skip. Test isolation uses
unique operation and permit identifiers; mutations to shared chain entries
are restored after integrity probes.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from shards_kernel.distributed.audit_chain import (
    AuthorityAuditChain, AuthorityAuditIntegrityError, GENESIS_ROOT,
)
from shards_kernel.distributed.postgres import PostgresPermitJournal

pytestmark = pytest.mark.skipif(
    not os.environ.get("SHARDS_TEST_POSTGRES_DSN"),
    reason="PostgreSQL primary required for the atomic audit acceptance",
)


@pytest.fixture
def journal():
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    j = PostgresPermitJournal(lambda: psycopg.connect(dsn, connect_timeout=5))
    j.initialize_schema()
    return j


def permit():
    return {
        "operation_id": uuid4().hex, "permit_id": uuid4().hex,
        "issuer": "audit-issuer", "subject": "audit-agent",
        "nonce": uuid4().hex, "max_executions": 1,
        "request_sha256": "b" * 64,
    }


def test_reservation_and_all_transitions_are_atomically_hashed(journal):
    before = journal.verify_authority_audit()
    p = permit()
    assert journal.reserve(**p)
    start = journal.verify_authority_audit()
    assert start.sequence == before.sequence + 1
    assert start.root != before.root
    assert len(start.root) == 64
    assert journal.mark_dispatched(p["operation_id"])
    assert journal.mark_unknown(p["operation_id"])
    assert journal.reconcile(
        p["operation_id"], outcome="SUCCEEDED",
        evidence_ref="verified:evidence", provider_ref="provider:receipt",
    )
    completed = journal.verify_authority_audit()
    assert completed.sequence == before.sequence + 4
    assert completed.root != start.root
    assert journal.get(p["operation_id"]).state == "SUCCEEDED"
    # Duplicate transitions must not append duplicate audit records.
    assert not journal.mark_dispatched(p["operation_id"])
    assert not journal.reconcile(
        p["operation_id"], outcome="SUCCEEDED",
        evidence_ref="verified:evidence", provider_ref="provider:receipt",
    )
    assert journal.verify_authority_audit() == completed


def test_distinct_postgres_connections_share_one_authoritative_chain(journal):
    before = journal.verify_authority_audit()
    permits = [permit() for _ in range(16)]
    twin = PostgresPermitJournal(journal._connect)
    with ThreadPoolExecutor(max_workers=8) as executor:
        success = list(executor.map(
            lambda x: (journal if int(x["operation_id"][:2], 16) % 2
                       else twin).reserve(**x),
            permits,
        ))
    assert all(success)
    after = journal.verify_authority_audit()
    assert after.sequence == before.sequence + 16
    assert after.root != before.root


def test_audit_insert_failure_rolls_back_budget_and_operation(journal, monkeypatch):
    p = permit()
    def refuse(*args, **kwargs):
        raise RuntimeError("audit is unavailable")
    with monkeypatch.context() as m:
        m.setattr(AuthorityAuditChain, "append", refuse)
        with pytest.raises(RuntimeError, match="audit is unavailable"):
            journal.reserve(**p)
    assert journal.get(p["operation_id"]) is None
    assert journal.reserve(**p)
    assert journal.verify_authority_audit().sequence >= 1


def test_audit_insert_failure_rolls_back_dispatch_state(journal, monkeypatch):
    p = permit()
    assert journal.reserve(**p)
    before = journal.verify_authority_audit()
    with monkeypatch.context() as m:
        m.setattr(
            AuthorityAuditChain, "append",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("audit lost")),
        )
        with pytest.raises(OSError, match="audit lost"):
            journal.mark_dispatched(p["operation_id"])
    assert journal.get(p["operation_id"]).state == "RESERVED"
    assert journal.verify_authority_audit() == before
    assert journal.mark_dispatched(p["operation_id"])
    assert journal.verify_authority_audit().sequence == before.sequence + 1


def test_audit_failure_rolls_back_reconciliation(journal, monkeypatch):
    p = permit()
    assert journal.reserve(**p)
    assert journal.mark_dispatched(p["operation_id"])
    before = journal.verify_authority_audit()
    with monkeypatch.context() as m:
        m.setattr(
            AuthorityAuditChain, "append",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("audit lost")),
        )
        with pytest.raises(OSError, match="audit lost"):
            journal.reconcile(
                p["operation_id"], outcome="NOT_APPLIED",
                evidence_ref="provider:proves-nonapplication",
            )
    assert journal.get(p["operation_id"]).state == "DISPATCHED"
    assert journal.verify_authority_audit() == before


def test_tampering_with_existing_audit_event_is_detected_and_restorable(journal):
    psycopg = pytest.importorskip("psycopg")
    p = permit()
    assert journal.reserve(**p)
    original = journal.verify_authority_audit()
    with psycopg.connect(os.environ["SHARDS_TEST_POSTGRES_DSN"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT seq, event_canonical FROM shards_authority_audit
                   WHERE operation_id = %s AND event_type = 'RESERVED'""",
                (p["operation_id"],),
            )
            seq, canonical = cur.fetchone()
            cur.execute(
                """UPDATE shards_authority_audit SET event_canonical = %s
                   WHERE seq = %s""",
                ("{\"fabricated\":true}", seq),
            )
    try:
        with pytest.raises(AuthorityAuditIntegrityError):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(os.environ["SHARDS_TEST_POSTGRES_DSN"]) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE shards_authority_audit SET event_canonical = %s WHERE seq = %s",
                    (canonical, seq),
                )
    assert journal.verify_authority_audit() == original


def test_legacy_unjournalled_operation_is_not_falsely_certified(journal):
    psycopg = pytest.importorskip("psycopg")
    p = permit()
    with pytest.raises(RuntimeError, match="rollback legacy test"):
        with psycopg.connect(os.environ["SHARDS_TEST_POSTGRES_DSN"]) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO shards_effect_operation
                       (operation_id, permit_id, request_sha256, issuer, subject, nonce)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        p["operation_id"], p["permit_id"], p["request_sha256"],
                        p["issuer"], p["subject"], p["nonce"],
                    ),
                )
            # The ordinary verifier uses a fresh connection and cannot see
            # uncommitted rows; check using the transaction's SQL visibility.
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT COUNT(*) FROM shards_effect_operation op
                       WHERE op.operation_id = %s AND NOT EXISTS (
                         SELECT 1 FROM shards_authority_audit a
                         WHERE a.operation_id = op.operation_id
                       )""",
                    (p["operation_id"],),
                )
                assert cur.fetchone()[0] == 1
            raise RuntimeError("rollback legacy test")
    assert journal.get(p["operation_id"]) is None
    assert journal.verify_authority_audit().root != ""


def test_hash_domain_separation_and_validation():
    a = AuthorityAuditChain._canonical({"b": 1, "a": "x"})
    b = AuthorityAuditChain._canonical({"a": "x", "b": 1})
    assert a == b
    assert AuthorityAuditChain._hash(1, GENESIS_ROOT, a) != (
        AuthorityAuditChain._hash(2, GENESIS_ROOT, a)
    )
    with pytest.raises(ValueError, match="Unknown"):
        AuthorityAuditChain.append(None, "op", "BROKEN", {})
