"""Transactional, hash-linked PostgreSQL authority audit for shared permits.

Every event is appended with the caller's *existing* PostgreSQL transaction
and cursor. The single locked chain-head row serialises concurrent writers.
This detects accidental modification, omission, and local corruption on
verification. It is NOT a cryptographic external anti-rollback anchor.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

GENESIS_ROOT = "0" * 64
_ALLOWED_EVENTS = frozenset(
    {"RESERVED", "DISPATCHED", "UNKNOWN", "SUCCEEDED", "NOT_APPLIED"}
)
_PREVIOUS_STATES = {
    "RESERVED": frozenset({None}),
    "DISPATCHED": frozenset({"RESERVED"}),
    "UNKNOWN": frozenset({"DISPATCHED"}),
    "SUCCEEDED": frozenset({"DISPATCHED", "UNKNOWN"}),
    "NOT_APPLIED": frozenset({"DISPATCHED", "UNKNOWN"}),
}
_IDENTITY_FIELDS = ("permit_id", "request_sha256", "issuer", "subject", "nonce")

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS shards_authority_audit_head (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_seq BIGINT NOT NULL CHECK (last_seq >= 0),
    last_hash CHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS shards_authority_audit (
    seq BIGINT PRIMARY KEY CHECK (seq > 0),
    operation_id TEXT NOT NULL
        REFERENCES shards_effect_operation(operation_id),
    event_type TEXT NOT NULL
        CHECK (event_type IN ('RESERVED', 'DISPATCHED', 'UNKNOWN', 'SUCCEEDED', 'NOT_APPLIED')),
    event_canonical TEXT NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    entry_hash CHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shards_authority_audit_operation_idx
    ON shards_authority_audit (operation_id, seq);
INSERT INTO shards_authority_audit_head (singleton, last_seq, last_hash)
VALUES (TRUE, 0, '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (singleton) DO NOTHING;
"""


class AuthorityAuditIntegrityError(RuntimeError):
    """The shared authority audit is missing, broken or not reconcilable."""


@dataclass(frozen=True)
class AuthorityAuditSnapshot:
    """Locally verified chain view, NOT an independently anchored checkpoint."""

    sequence: int
    root: str


class AuthorityAuditChain:
    """PostgreSQL-backed global event chain with no autonomous commits."""

    @staticmethod
    def initialize_schema(cur: Any) -> None:
        """Create audit structures in the same privileged migration transaction."""
        cur.execute(AUDIT_SCHEMA)

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> str:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )

    @staticmethod
    def _hash(sequence: int, previous: str, event_canonical: str) -> str:
        payload = (
            "SHARDS-POSTGRES-AUTHORITY-AUDIT-V1\n"
            + str(sequence) + "\n" + previous + "\n" + event_canonical
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def append(
        cls, cur: Any, operation_id: str, event_type: str, fields: dict[str, Any],
    ) -> str:
        """Append event atomically alongside caller's permit/effect mutation.

        Caller MUST be inside one writable PostgreSQL transaction. Any
        database failure aborts permit consumption and audit together.
        """
        if event_type not in _ALLOWED_EVENTS:
            raise ValueError("Unknown authority event type")
        canonical = cls._canonical({
            "event": event_type,
            "operation_id": operation_id,
            "fields": fields,
        })
        cur.execute(
            """SELECT last_seq, last_hash FROM shards_authority_audit_head
               WHERE singleton = TRUE FOR UPDATE"""
        )
        head = cur.fetchone()
        if head is None:
            raise AuthorityAuditIntegrityError("Authority chain head missing")
        current_seq, current_hash = head
        cur.execute(
            """SELECT seq, entry_hash FROM shards_authority_audit
               ORDER BY seq DESC LIMIT 1"""
        )
        last = cur.fetchone()
        if (
            (last is None and (current_seq != 0 or current_hash != GENESIS_ROOT))
            or (last is not None and (last[0] != current_seq or last[1] != current_hash))
        ):
            raise AuthorityAuditIntegrityError("Authority chain head disagrees with log")
        # Validate the sequence *within* each operation as well as the
        # global hash link. A forged skipped transition must never be
        # appended even if its hash would be internally self-consistent.
        cur.execute(
            """SELECT event_type FROM shards_authority_audit
               WHERE operation_id = %s ORDER BY seq DESC LIMIT 1""",
            (operation_id,),
        )
        prior = cur.fetchone()
        prior_state = prior[0] if prior is not None else None
        if prior_state not in _PREVIOUS_STATES[event_type]:
            raise AuthorityAuditIntegrityError("Invalid authority operation transition")
        next_seq = current_seq + 1
        entry_hash = cls._hash(next_seq, current_hash, canonical)
        cur.execute(
            """INSERT INTO shards_authority_audit
               (seq, operation_id, event_type, event_canonical, prev_hash, entry_hash)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (next_seq, operation_id, event_type, canonical, current_hash, entry_hash),
        )
        cur.execute(
            """UPDATE shards_authority_audit_head
               SET last_seq = %s, last_hash = %s WHERE singleton = TRUE""",
            (next_seq, entry_hash),
        )
        return entry_hash

    @classmethod
    def _decode_event(
        cls, operation_id: str, event_type: str, canonical: str,
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        """Validate canonical event content and the immutable identity fields."""
        try:
            decoded = json.loads(canonical)
            if (
                decoded.get("event") != event_type
                or decoded.get("operation_id") != operation_id
                or cls._canonical(decoded) != canonical
            ):
                raise AuthorityAuditIntegrityError("Authority event payload mismatch")
            fields = decoded.get("fields")
            if not isinstance(fields, dict):
                raise AuthorityAuditIntegrityError("Authority event missing fields")
            identity = tuple(fields.get(key) for key in _IDENTITY_FIELDS)
            if any(not isinstance(item, str) or not item for item in identity):
                raise AuthorityAuditIntegrityError("Authority event identity incomplete")
            return fields, identity
        except (TypeError, ValueError, AttributeError) as exc:
            raise AuthorityAuditIntegrityError("Malformed authority event payload") from exc

    @staticmethod
    def _verify_operation_event(
        operation_id: str,
        event_type: str,
        fields: dict[str, Any],
        identity: tuple[str, ...],
        states: dict[str, str],
        identities: dict[str, tuple[str, ...]],
    ) -> None:
        """Prevent skipped transitions and identity drift in hash-valid logs."""
        if states.get(operation_id) not in _PREVIOUS_STATES[event_type]:
            raise AuthorityAuditIntegrityError("Invalid authority operation history")
        if event_type == "RESERVED":
            limit = fields.get("max_executions")
            used = fields.get("use_count")
            if (
                type(limit) is not int or limit < 1
                or type(used) is not int or not 1 <= used <= limit
            ):
                raise AuthorityAuditIntegrityError("Malformed permit reservation evidence")
            identities[operation_id] = identity
        elif identities.get(operation_id) != identity:
            raise AuthorityAuditIntegrityError("Operation identity changed across events")

    @classmethod
    def _verify_entries(
        cls, rows: list[tuple[Any, ...]],
    ) -> tuple[int, str, dict[str, str], dict[str, tuple[str, ...]]]:
        """Walk the complete chain, checking cryptographic and semantic links."""
        seq, root = 0, GENESIS_ROOT
        states: dict[str, str] = {}
        identities: dict[str, tuple[str, ...]] = {}
        for number, operation_id, event_type, canonical, previous, digest in rows:
            seq += 1
            if number != seq or previous != root or event_type not in _ALLOWED_EVENTS:
                raise AuthorityAuditIntegrityError("Authority event order or link invalid")
            fields, identity = cls._decode_event(operation_id, event_type, canonical)
            cls._verify_operation_event(
                operation_id, event_type, fields, identity, states, identities,
            )
            if digest != cls._hash(seq, root, canonical):
                raise AuthorityAuditIntegrityError("Authority event hash mismatch")
            root = digest
            states[operation_id] = event_type
        return seq, root, states, identities

    @staticmethod
    def _verify_operation_projection(
        operation_rows: list[tuple[Any, ...]],
        states: dict[str, str],
        identities: dict[str, tuple[str, ...]],
    ) -> None:
        """Reject legacy rows, missing operations and state/permit substitution."""
        if len(operation_rows) != len(states):
            raise AuthorityAuditIntegrityError("Unjournalled operation count mismatch")
        for op_id, state, permit_id, request_hash, issuer, subject, nonce in operation_rows:
            if (
                states.get(op_id) != state
                or identities.get(op_id) != (
                    permit_id, request_hash, issuer, subject, nonce
                )
            ):
                raise AuthorityAuditIntegrityError(
                    "Unjournalled operation or effect-state mismatch"
                )

    @classmethod
    def verify(cls, conn: Any) -> AuthorityAuditSnapshot:
        """Verify on-primary history and operation projection within one transaction.

        A privileged database rollback still requires an external trusted
        checkpoint: this verifier alone cannot prove off-primary provenance.
        """
        with conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """SELECT last_seq, last_hash FROM shards_authority_audit_head
                           WHERE singleton = TRUE FOR SHARE"""
                    )
                    head = cur.fetchone()
                    if head is None:
                        raise AuthorityAuditIntegrityError("Authority chain head missing")
                    cur.execute(
                        """SELECT seq, operation_id, event_type, event_canonical,
                                  prev_hash, entry_hash
                           FROM shards_authority_audit ORDER BY seq"""
                    )
                    seq, root, states, identities = cls._verify_entries(cur.fetchall())
                    if (seq, root) != (head[0], head[1]):
                        raise AuthorityAuditIntegrityError("Authority head does not match history")
                    cur.execute(
                        """SELECT operation_id, state, permit_id, request_sha256,
                                  issuer, subject, nonce
                           FROM shards_effect_operation"""
                    )
                    cls._verify_operation_projection(cur.fetchall(), states, identities)
                    return AuthorityAuditSnapshot(sequence=seq, root=root)
