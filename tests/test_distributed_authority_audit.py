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


def _assert_failed_audit_append(monkeypatch, operation):
    """One failure injector shared by the reservation/transition invariants."""
    def fail(*args, **kwargs):
        raise OSError("audit lost")

    with monkeypatch.context() as patch:
        patch.setattr(AuthorityAuditChain, "append", fail)
        with pytest.raises(OSError, match="audit lost"):
            operation()


def test_audit_insert_failure_rolls_back_budget_and_operation(journal, monkeypatch):
    p = permit()
    _assert_failed_audit_append(monkeypatch, lambda: journal.reserve(**p))
    assert journal.get(p["operation_id"]) is None
    assert journal.reserve(**p)
    assert journal.verify_authority_audit().sequence >= 1


def test_audit_insert_failure_rolls_back_dispatch_state(journal, monkeypatch):
    p = permit()
    assert journal.reserve(**p)
    before = journal.verify_authority_audit()
    _assert_failed_audit_append(
        monkeypatch, lambda: journal.mark_dispatched(p["operation_id"])
    )
    assert journal.get(p["operation_id"]).state == "RESERVED"
    assert journal.verify_authority_audit() == before
    assert journal.mark_dispatched(p["operation_id"])
    assert journal.verify_authority_audit().sequence == before.sequence + 1


def test_audit_failure_rolls_back_reconciliation(journal, monkeypatch):
    p = permit()
    assert journal.reserve(**p)
    assert journal.mark_dispatched(p["operation_id"])
    before = journal.verify_authority_audit()
    _assert_failed_audit_append(
        monkeypatch,
        lambda: journal.reconcile(
            p["operation_id"], outcome="NOT_APPLIED",
            evidence_ref="provider:proves-nonapplication",
        ),
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


def test_hash_domain_separation_and_validation():
    a = AuthorityAuditChain._canonical({"b": 1, "a": "x"})
    b = AuthorityAuditChain._canonical({"a": "x", "b": 1})
    assert a == b
    assert AuthorityAuditChain._hash(1, GENESIS_ROOT, a) != (
        AuthorityAuditChain._hash(2, GENESIS_ROOT, a)
    )
    with pytest.raises(ValueError, match="Unknown"):
        AuthorityAuditChain.append(None, "op", "BROKEN", {})


def test_missing_global_head_refuses_reservation_and_verification(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    # Deliberate hostile administrative change; restore in all circumstances.
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """DELETE FROM shards_authority_audit_head
                   WHERE singleton = TRUE RETURNING last_seq, last_hash"""
            )
            original = cur.fetchone()
    assert original is not None
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="head missing"):
            journal.verify_authority_audit()
        p = permit()
        with pytest.raises(AuthorityAuditIntegrityError, match="head missing"):
            journal.reserve(**p)
        assert journal.get(p["operation_id"]) is None
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO shards_authority_audit_head
                       (singleton, last_seq, last_hash) VALUES (TRUE, %s, %s)""",
                    original,
                )
    journal.verify_authority_audit()


def test_corrupted_head_fails_closed_before_new_consumption(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE shards_authority_audit_head SET last_hash = %s
                   WHERE singleton = TRUE RETURNING last_hash""",
                ("f" * 64,),
            )
    # Head may have matched the tampered value before the update, so use the
    # known verified pre-tamper state from a fresh operation in this test.
    # Re-read the last durable event to restore the legitimate head.
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="head disagrees"):
            journal.reserve(**permit())
        with pytest.raises(AuthorityAuditIntegrityError, match="head does not match"):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT seq, entry_hash FROM shards_authority_audit ORDER BY seq DESC LIMIT 1"
                )
                last = cur.fetchone()
                seq, digest = last if last is not None else (0, GENESIS_ROOT)
                cur.execute(
                    """UPDATE shards_authority_audit_head
                       SET last_seq = %s, last_hash = %s WHERE singleton = TRUE""",
                    (seq, digest),
                )
    journal.verify_authority_audit()


@pytest.mark.parametrize(
    "field,bad_value,reason",
    [
        ("prev_hash", "f" * 64, "order or link"),
        ("event_canonical", "{not valid json", "Malformed authority"),
        ("entry_hash", "f" * 64, "hash mismatch"),
    ],
)
def test_corruption_variants_are_detected(journal, field, bad_value, reason):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    assert journal.reserve(**p)
    # Explicit, static statements avoid dynamic SQL interpolation even in
    # adversarial tests. Only the values are bound at runtime.
    statements = {
        "prev_hash": (
            "SELECT prev_hash FROM shards_authority_audit WHERE operation_id = %s",
            "UPDATE shards_authority_audit SET prev_hash = %s WHERE operation_id = %s",
        ),
        "event_canonical": (
            "SELECT event_canonical FROM shards_authority_audit WHERE operation_id = %s",
            "UPDATE shards_authority_audit SET event_canonical = %s WHERE operation_id = %s",
        ),
        "entry_hash": (
            "SELECT entry_hash FROM shards_authority_audit WHERE operation_id = %s",
            "UPDATE shards_authority_audit SET entry_hash = %s WHERE operation_id = %s",
        ),
    }
    select_sql, update_sql = statements[field]
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(select_sql, (p["operation_id"],))
            original = cur.fetchone()[0]
            cur.execute(update_sql, (bad_value, p["operation_id"]))
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match=reason):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(update_sql, (original, p["operation_id"]))
    journal.verify_authority_audit()


def test_operation_state_drift_without_audit_event_is_detected(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    assert journal.reserve(**p)
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE shards_effect_operation SET state = 'UNKNOWN'
                   WHERE operation_id = %s""",
                (p["operation_id"],),
            )
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="state mismatch"):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE shards_effect_operation SET state = 'RESERVED'
                       WHERE operation_id = %s""",
                    (p["operation_id"],),
                )
    journal.verify_authority_audit()


def test_committed_pre_migration_intent_is_reported_as_history_gap(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    with psycopg.connect(dsn) as conn:
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
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="Unjournalled"):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM shards_effect_operation WHERE operation_id = %s",
                    (p["operation_id"],),
                )
    journal.verify_authority_audit()


def test_append_rejects_skipped_state_transition(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    assert journal.reserve(**p)
    before = journal.verify_authority_audit()
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            with pytest.raises(
                AuthorityAuditIntegrityError, match="Invalid authority operation transition"
            ):
                AuthorityAuditChain.append(
                    cur, p["operation_id"], "SUCCEEDED",
                    {"permit_id": p["permit_id"], "request_sha256": p["request_sha256"]},
                )
    assert journal.verify_authority_audit() == before


def test_self_consistent_hash_forgery_cannot_skip_operation_transition(journal):
    """Simulate a privileged actor recomputing the chain to conceal skipped dispatch."""
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    assert journal.reserve(**p)
    verified = journal.verify_authority_audit()
    seq = verified.sequence + 1
    canonical = AuthorityAuditChain._canonical({
        "event": "SUCCEEDED",
        "operation_id": p["operation_id"],
        "fields": {
            "permit_id": p["permit_id"],
            "request_sha256": p["request_sha256"],
            "issuer": p["issuer"],
            "subject": p["subject"],
            "nonce": p["nonce"],
            "evidence_ref": "forged",
            "provider_ref": "forged",
        },
    })
    digest = AuthorityAuditChain._hash(seq, verified.root, canonical)
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO shards_authority_audit
                   (seq, operation_id, event_type, event_canonical, prev_hash, entry_hash)
                   VALUES (%s, %s, 'SUCCEEDED', %s, %s, %s)""",
                (seq, p["operation_id"], canonical, verified.root, digest),
            )
            cur.execute(
                """UPDATE shards_authority_audit_head SET last_seq=%s, last_hash=%s
                   WHERE singleton=TRUE""",
                (seq, digest),
            )
            cur.execute(
                """UPDATE shards_effect_operation SET state='SUCCEEDED'
                   WHERE operation_id=%s""",
                (p["operation_id"],),
            )
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="Invalid authority operation history"):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM shards_authority_audit WHERE seq=%s", (seq,))
                cur.execute(
                    """UPDATE shards_authority_audit_head SET last_seq=%s, last_hash=%s
                       WHERE singleton=TRUE""",
                    (verified.sequence, verified.root),
                )
                cur.execute(
                    """UPDATE shards_effect_operation SET state='RESERVED'
                       WHERE operation_id=%s""",
                    (p["operation_id"],),
                )
    assert journal.verify_authority_audit() == verified


def test_self_consistent_hash_forgery_cannot_change_permit_identity(journal):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["SHARDS_TEST_POSTGRES_DSN"]
    p = permit()
    assert journal.reserve(**p)
    before = journal.verify_authority_audit()
    seq = before.sequence + 1
    canonical = AuthorityAuditChain._canonical({
        "event": "DISPATCHED", "operation_id": p["operation_id"],
        "fields": {
            "permit_id": "forged-permit",
            "request_sha256": p["request_sha256"],
            "issuer": p["issuer"], "subject": p["subject"],
            "nonce": p["nonce"],
        },
    })
    digest = AuthorityAuditChain._hash(seq, before.root, canonical)
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO shards_authority_audit
                   (seq, operation_id, event_type, event_canonical, prev_hash, entry_hash)
                   VALUES (%s, %s, 'DISPATCHED', %s, %s, %s)""",
                (seq, p["operation_id"], canonical, before.root, digest),
            )
            cur.execute(
                """UPDATE shards_authority_audit_head SET last_seq=%s, last_hash=%s
                   WHERE singleton=TRUE""",
                (seq, digest),
            )
            cur.execute(
                """UPDATE shards_effect_operation SET state='DISPATCHED'
                   WHERE operation_id=%s""",
                (p["operation_id"],),
            )
    try:
        with pytest.raises(AuthorityAuditIntegrityError, match="Operation identity changed"):
            journal.verify_authority_audit()
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM shards_authority_audit WHERE seq=%s", (seq,))
                cur.execute(
                    """UPDATE shards_authority_audit_head SET last_seq=%s, last_hash=%s
                       WHERE singleton=TRUE""",
                    (before.sequence, before.root),
                )
                cur.execute(
                    """UPDATE shards_effect_operation SET state='RESERVED'
                       WHERE operation_id=%s""",
                    (p["operation_id"],),
                )
    assert journal.verify_authority_audit() == before
