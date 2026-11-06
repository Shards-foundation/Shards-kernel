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
    first_root = AuthorityAuditChain.append(cur, "op", "RESERVED", fields())
    second_root = AuthorityAuditChain.append(
        cur, "op", "DISPATCHED",
        {k: fields()[k] for k in (
            "permit_id", "request_sha256", "issuer", "subject", "nonce"
        )},
    )
    assert first_root != second_root
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
    initial_root = AuthorityAuditChain.append(
        conn.cursor(), "op", "RESERVED", fields()
    )
    assert len(initial_root) == 64
    with pytest.raises(AuthorityAuditIntegrityError, match="Invalid authority"):
        AuthorityAuditChain.append(conn.cursor(), "op", "RESERVED", fields())


def test_verifier_empty_clean_state_and_missing_head():
    conn = MemoryConnection()
    assert AuthorityAuditChain.verify(conn) == AuthorityAuditSnapshot(0, GENESIS_ROOT)
    conn.head = None
    with pytest.raises(AuthorityAuditIntegrityError, match="head missing"):
        AuthorityAuditChain.verify(conn)


def _rewrite_forged_event(conn: MemoryConnection, change: str) -> MemoryConnection:
    """Re-hash a deliberately malformed event so semantic checks run first."""
    rows = list(conn.rows)
    is_reserved = change == "bad_budget"
    index = 0 if is_reserved else 1
    event_type = "RESERVED" if is_reserved else "DISPATCHED"
    bad_fields = {
        "empty_fields": None,
        "empty_identity": {**fields(), "permit_id": ""},
        "bad_budget": {**fields(), "use_count": 0},
    }[change]
    previous = rows[index][4]
    canonical = AuthorityAuditChain._canonical({
        "event": event_type, "operation_id": "op", "fields": bad_fields,
    })
    digest = AuthorityAuditChain._hash(index + 1, previous, canonical)
    rows[index] = (index + 1, "op", event_type, canonical, previous, digest)
    if is_reserved:
        second = rows[1]
        second_digest = AuthorityAuditChain._hash(2, digest, second[3])
        rows[1] = (2, "op", "DISPATCHED", second[3], digest, second_digest)
        conn.head = (2, second_digest)
    else:
        conn.head = (2, digest)
    conn.rows = rows
    return conn


def _corrupted_chain(change: str) -> MemoryConnection:
    """Build each malformed case without a long branch-heavy test function."""
    if change == "identity":
        return build_chain(overrides={2: {"permit_id": "evil"}})
    if change == "skip":
        return build_chain(("RESERVED", "SUCCEEDED"))
    conn = build_chain()
    if change in {"empty_fields", "empty_identity", "bad_budget"}:
        return _rewrite_forged_event(conn, change)

    row = conn.rows[1]
    mutations = {
        "seq": (9, *row[1:]),
        "prev": (*row[:4], "f" * 64, row[5]),
        "event": (row[0], row[1], "BROKEN", *row[3:]),
        "bad_json": (*row[:3], "{bad", *row[4:]),
        "payload": (*row[:3], json.dumps({"event": "WRONG"}), *row[4:]),
        "digest": (*row[:5], "f" * 64),
    }
    if change in mutations:
        conn.rows[1] = mutations[change]
    elif change == "head":
        conn.head = (2, "f" * 64)
    elif change == "state":
        conn.operations = [operation("UNKNOWN")]
    elif change == "legacy":
        conn.operations.append((
            "legacy", "RESERVED", "permit", "a" * 64,
            "issuer", "subject", "nonce",
        ))
    else:
        raise ValueError("Unsupported adversarial test case")
    return conn


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
    with pytest.raises(AuthorityAuditIntegrityError, match=reason):
        AuthorityAuditChain.verify(_corrupted_chain(change))
