"""Fast authority-chain contract tests for every supported Python version.

Mocked cursor tests cover deterministic validation paths. They do NOT prove
database transactionality; real PostgreSQL tests are separately mandatory.
"""

from __future__ import annotations

import json

import pytest

from shards_kernel.distributed.audit_chain import (
    AuthorityAuditChain,
    AuthorityAuditIntegrityError,
    AuthorityAuditSnapshot,
    GENESIS_ROOT,
)


class MemoryConnection:
    def __init__(self, *, rows=None, head=None, operations=None):
        self.rows = list(rows or [])
        self.head = head if head is not None else (0, GENESIS_ROOT)
        self.operations = list(operations or [])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def transaction(self):
        return self

    def cursor(self):
        return MemoryCursor(self)


class MemoryCursor:
    def __init__(self, conn):
        self.conn = conn
        self.one = None
        self.all = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, values=None):
        normalized = " ".join(sql.split()).lower()
        if normalized.startswith("create table"):
            return
        if "select last_seq, last_hash from shards_authority_audit_head" in normalized:
            self.one = self.conn.head
            return
        if "select seq, entry_hash from shards_authority_audit" in normalized:
            row = self.conn.rows[-1] if self.conn.rows else None
            self.one = (row[0], row[5]) if row else None
            return
        if "select event_type from shards_authority_audit" in normalized:
            relevant = [r for r in self.conn.rows if r[1] == values[0]]
            self.one = (relevant[-1][2],) if relevant else None
            return
        if normalized.startswith("insert into shards_authority_audit"):
            seq, operation_id, kind, canonical, prev, digest = values
            self.conn.rows.append((seq, operation_id, kind, canonical, prev, digest))
            return
        if normalized.startswith("update shards_authority_audit_head"):
            self.conn.head = (values[0], values[1])
            return
        if "select seq, operation_id, event_type, event_canonical" in normalized:
            self.all = list(self.conn.rows)
            return
        if "select operation_id, state, permit_id, request_sha256" in normalized:
            self.all = list(self.conn.operations)
            return
        raise AssertionError("Unexpected simulated SQL: " + normalized[:80])

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.all


def fields():
    return {
        "permit_id": "permit", "request_sha256": "a" * 64,
        "issuer": "issuer", "subject": "subject", "nonce": "nonce",
        "max_executions": 1, "use_count": 1,
    }


def operation(state):
    return ("op", state, "permit", "a" * 64, "issuer", "subject", "nonce")


def build_chain(events=("RESERVED", "DISPATCHED"), *, overrides=None):
    rows = []
    root = GENESIS_ROOT
    for number, kind in enumerate(events, 1):
        event_fields = fields()
        if kind != "RESERVED":
            event_fields = {k: event_fields[k] for k in (
                "permit_id", "request_sha256", "issuer", "subject", "nonce"
            )}
        if overrides and number in overrides:
            event_fields.update(overrides[number])
        canonical = AuthorityAuditChain._canonical({
            "event": kind, "operation_id": "op", "fields": event_fields,
        })
        digest = AuthorityAuditChain._hash(number, root, canonical)
        rows.append((number, "op", kind, canonical, root, digest))
        root = digest
    return MemoryConnection(rows=rows, head=(len(rows), root), operations=[
        operation(events[-1])
    ])


def test_append_and_verify_happy_path_without_real_database():
    conn = MemoryConnection()
    cur = conn.cursor()
    AuthorityAuditChain.initialize_schema(cur)
    assert AuthorityAuditChain.append(cur, "op", "RESERVED", fields())
    assert AuthorityAuditChain.append(
        cur, "op", "DISPATCHED",
        {k: fields()[k] for k in (
            "permit_id", "request_sha256", "issuer", "subject", "nonce"
        )},
    )
    conn.operations = [operation("DISPATCHED")]
    result = AuthorityAuditChain.verify(conn)
    assert isinstance(result, AuthorityAuditSnapshot)
    assert result.sequence == 2
    assert result.root == conn.head[1]


def test_append_fails_closed_when_head_missing_or_tampered():
    for broken in (None, (0, "f" * 64)):
        conn = MemoryConnection()
        conn.head = broken
        with pytest.raises(AuthorityAuditIntegrityError, match="head missing|head disagrees"):
            AuthorityAuditChain.append(conn.cursor(), "op", "RESERVED", fields())
    conn = build_chain(("RESERVED",))
    conn.head = (2, conn.head[1])
    with pytest.raises(AuthorityAuditIntegrityError, match="head disagrees"):
        AuthorityAuditChain.append(conn.cursor(), "other", "RESERVED", fields())


def test_append_refuses_invalid_operation_order():
    conn = MemoryConnection()
    with pytest.raises(ValueError, match="Unknown"):
        AuthorityAuditChain.append(conn.cursor(), "op", "INVALID", fields())
    with pytest.raises(AuthorityAuditIntegrityError, match="Invalid authority"):
        AuthorityAuditChain.append(conn.cursor(), "op", "SUCCEEDED", fields())
    assert AuthorityAuditChain.append(conn.cursor(), "op", "RESERVED", fields())
    with pytest.raises(AuthorityAuditIntegrityError, match="Invalid authority"):
        AuthorityAuditChain.append(conn.cursor(), "op", "RESERVED", fields())


def test_verifier_empty_clean_state_and_missing_head():
    conn = MemoryConnection()
    assert AuthorityAuditChain.verify(conn) == AuthorityAuditSnapshot(0, GENESIS_ROOT)
    conn.head = None
    with pytest.raises(AuthorityAuditIntegrityError, match="head missing"):
        AuthorityAuditChain.verify(conn)


@pytest.mark.parametrize("change,reason", [
    ("seq", "order or link"),
    ("prev", "order or link"),
    ("event", "order or link"),
    ("bad_json", "Malformed authority event"),
    ("payload", "payload mismatch"),
    ("digest", "hash mismatch"),
    ("head", "head does not match"),
    ("state", "state mismatch"),
    ("legacy", "Unjournalled operation count"),
    ("identity", "Operation identity changed"),
    ("skip", "Invalid authority operation history"),
    ("empty_fields", "missing fields"),
    ("empty_identity", "identity incomplete"),
    ("bad_budget", "Malformed permit reservation evidence"),
])
def test_semantic_and_cryptographic_failures(change, reason):
    conn = build_chain()
    rows = list(conn.rows)
    seq, op, kind, canon, prev, digest = rows[1]
    if change == "seq":
        rows[1] = (9, op, kind, canon, prev, digest)
    elif change == "prev":
        rows[1] = (seq, op, kind, canon, "f" * 64, digest)
    elif change == "event":
        rows[1] = (seq, op, "BROKEN", canon, prev, digest)
    elif change == "bad_json":
        rows[1] = (seq, op, kind, "{bad", prev, digest)
    elif change == "payload":
        rows[1] = (seq, op, kind, json.dumps({"event": "WRONG"}), prev, digest)
    elif change == "digest":
        rows[1] = (seq, op, kind, canon, prev, "f" * 64)
    elif change == "head":
        conn.head = (2, "f" * 64)
    elif change == "state":
        conn.operations = [operation("UNKNOWN")]
    elif change == "legacy":
        conn.operations.append(("legacy", "RESERVED", "permit", "a" * 64,
                                "issuer", "subject", "nonce"))
    elif change == "identity":
        conn = build_chain(overrides={2: {"permit_id": "evil"}})
    elif change == "skip":
        conn = build_chain(("RESERVED", "SUCCEEDED"))
    elif change in ("empty_fields", "empty_identity", "bad_budget"):
        field_value = (
            None if change == "empty_fields"
            else {**fields(), "permit_id": ""} if change == "empty_identity"
            else {**fields(), "use_count": 0}
        )
        if change != "bad_budget":
            target_index = 2
            target_kind = "DISPATCHED"
            target_fields = field_value
        else:
            target_index = 1
            target_kind = "RESERVED"
            target_fields = field_value
        idx = target_index - 1
        old = rows[idx]
        forged = AuthorityAuditChain._canonical({
            "event": target_kind, "operation_id": "op",
            "fields": target_fields,
        })
        prev_hash = old[4]
        revised_digest = AuthorityAuditChain._hash(target_index, prev_hash, forged)
        rows[idx] = (target_index, "op", target_kind, forged, prev_hash, revised_digest)
        # Update subsequent links so only the intended semantic check fails.
        if idx == 0:
            next_old = rows[1]
            next_digest = AuthorityAuditChain._hash(2, revised_digest, next_old[3])
            rows[1] = (2, "op", "DISPATCHED", next_old[3], revised_digest, next_digest)
            conn.head = (2, next_digest)
        else:
            conn.head = (2, revised_digest)
    conn.rows = rows if change not in ("identity", "skip") else conn.rows
    with pytest.raises(AuthorityAuditIntegrityError, match=reason):
        AuthorityAuditChain.verify(conn)
