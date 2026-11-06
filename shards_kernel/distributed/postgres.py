"""Opt-in cross-host permit accounting and external-effect reconciliation journal.

This module is deliberately NOT wired into BaseKernel or the single-host
operator service. It requires a PostgreSQL primary, separately verified
permits, trusted dispatch adapters and an explicit migration before use.
It never issues permits or executes downstream actions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# PostgreSQL connections use the DB-API/psycopg context-manager interface.
# Importing this module does not require psycopg or make a network connection.
ConnectionFactory = Callable[[], Any]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS shards_permit_budget (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    nonce TEXT NOT NULL,
    permit_id TEXT NOT NULL,
    max_executions INTEGER NOT NULL CHECK (max_executions > 0),
    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0 AND used <= max_executions),
    PRIMARY KEY (issuer, subject, nonce)
);
CREATE TABLE IF NOT EXISTS shards_effect_operation (
    operation_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    nonce TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'RESERVED'
        CHECK (state IN ('RESERVED', 'DISPATCHED', 'UNKNOWN', 'SUCCEEDED', 'NOT_APPLIED')),
    evidence_ref TEXT,
    provider_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shards_effect_unresolved_idx
    ON shards_effect_operation (updated_at, operation_id)
    WHERE state IN ('RESERVED', 'DISPATCHED', 'UNKNOWN');
"""


class PermitAccountingError(RuntimeError):
    """Fail-closed accounting invariant violation or tampered permit identity."""


class _BudgetExhausted(Exception):
    """Roll back uncommitted intent and return a denial."""


@dataclass(frozen=True)
class EffectOperation:
    """Read-only journal projection. A state is NOT proof of provider truth."""

    operation_id: str
    permit_id: str
    request_sha256: str
    state: str
    evidence_ref: str | None
    provider_ref: str | None


class PostgresPermitJournal:
    """Transactional shared permit budget and conservative effect state machine.

    reserve() is called only AFTER an independently authenticated and signed
    permit has passed the kernel's full scope, time, actor and policy checks.
    A True result grants ONE new dispatch attempt, not universal exactly-once
    external effects. The caller must persist DISPATCHED before invoking a
    downstream provider and MUST NOT retry an uncertain operation automatically.

    Every API call creates a fresh primary DB connection. Any DB/partition
    failure propagates; no process-local or replica fallback is permitted.
    """

    def __init__(self, connection_factory: ConnectionFactory) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        self._connect = connection_factory

    def initialize_schema(self) -> None:
        """Apply idempotent schema using a privileged migration identity.

        Do not expose this operation to model-controlled tool execution.
        Production deployments should manage migrations out-of-band.
        """
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(_SCHEMA)

    @staticmethod
    def _identifier(value: str, field: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or not value.isascii():
            raise ValueError(field + " must be a nonempty ASCII identifier up to 256 bytes")
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
            raise ValueError(field + " contains whitespace or control characters")
        return value

    def reserve(
        self,
        *,
        operation_id: str,
        permit_id: str,
        issuer: str,
        subject: str,
        nonce: str,
        max_executions: int,
        request_sha256: str,
    ) -> bool:
        """Commit one global permit consumption plus its intent atomically.

        False means duplicate operation or exhausted budget: NEVER dispatch.
        Collision of an existing issuer/subject/nonce with different permit
        identity or maximum is a hard error. SQL-level locking serialises
        budget updates across independent hosts using the same primary.
        """
        operation_id = self._identifier(operation_id, "operation_id")
        permit_id = self._identifier(permit_id, "permit_id")
        issuer = self._identifier(issuer, "issuer")
        subject = self._identifier(subject, "subject")
        nonce = self._identifier(nonce, "nonce")
        if type(max_executions) is not int or max_executions < 1 or max_executions > 2147483647:
            raise ValueError("max_executions must be a positive PostgreSQL integer")
        if not isinstance(request_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None:
            raise ValueError("request_sha256 must be 64 lowercase hex characters")
        try:
            with self._connect() as conn:
                with conn.transaction():
                    with conn.cursor() as cur:
                        # A repeated operation ID is never another dispatch grant.
                        cur.execute(
                            """INSERT INTO shards_effect_operation
                               (operation_id, permit_id, request_sha256, issuer, subject, nonce)
                               VALUES (%s, %s, %s, %s, %s, %s)
                               ON CONFLICT (operation_id) DO NOTHING
                               RETURNING operation_id""",
                            (operation_id, permit_id, request_sha256, issuer, subject, nonce),
                        )
                        if cur.fetchone() is None:
                            return False
                        cur.execute(
                            """INSERT INTO shards_permit_budget
                               (issuer, subject, nonce, permit_id, max_executions)
                               VALUES (%s, %s, %s, %s, %s)
                               ON CONFLICT (issuer, subject, nonce) DO NOTHING""",
                            (issuer, subject, nonce, permit_id, max_executions),
                        )
                        cur.execute(
                            """SELECT permit_id, max_executions FROM shards_permit_budget
                               WHERE issuer = %s AND subject = %s AND nonce = %s
                               FOR UPDATE""",
                            (issuer, subject, nonce),
                        )
                        saved = cur.fetchone()
                        if saved is None or saved[0] != permit_id or saved[1] != max_executions:
                            raise PermitAccountingError("Nonce is bound to another permit or budget")
                        cur.execute(
                            """UPDATE shards_permit_budget SET used = used + 1
                               WHERE issuer = %s AND subject = %s AND nonce = %s
                                 AND used < max_executions RETURNING used""",
                            (issuer, subject, nonce),
                        )
                        if cur.fetchone() is None:
                            raise _BudgetExhausted()
            return True
        except _BudgetExhausted:
            # The transaction has rolled back the tentative intent INSERT.
            return False

    def mark_dispatched(self, operation_id: str) -> bool:
        """Grant the sole initial dispatch transition BEFORE the network call."""
        return self._transition(operation_id, "DISPATCHED", ("RESERVED",))

    def mark_unknown(self, operation_id: str) -> bool:
        """Quarantine an uncertain dispatched effect; no automatic retry."""
        return self._transition(operation_id, "UNKNOWN", ("DISPATCHED",))

    def reconcile(
        self,
        operation_id: str,
        *,
        outcome: str,
        evidence_ref: str,
        provider_ref: str = "",
    ) -> bool:
        """Close a dispatched/unknown effect with independently checked evidence.

        SUCCEEDED requires provider confirmation; NOT_APPLIED requires
        authoritative evidence that no effect occurred. This method stores a
        caller-supplied evidence reference; it does NOT verify provider truth.
        """
        if outcome not in ("SUCCEEDED", "NOT_APPLIED"):
            raise ValueError("Only verified SUCCEEDED or NOT_APPLIED may be reconciled")
        evidence_ref = self._identifier(evidence_ref, "evidence_ref")
        if outcome == "SUCCEEDED":
            provider_ref = self._identifier(provider_ref, "provider_ref")
        elif provider_ref:
            provider_ref = self._identifier(provider_ref, "provider_ref")
        operation_id = self._identifier(operation_id, "operation_id")
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE shards_effect_operation
                           SET state = %s, evidence_ref = %s, provider_ref = %s,
                               updated_at = now()
                           WHERE operation_id = %s AND state IN ('DISPATCHED', 'UNKNOWN')
                           RETURNING operation_id""",
                        (outcome, evidence_ref, provider_ref or None, operation_id),
                    )
                    return cur.fetchone() is not None

    def _transition(self, operation_id: str, target: str, sources: tuple[str, ...]) -> bool:
        operation_id = self._identifier(operation_id, "operation_id")
        if (target, sources) not in (
            ("DISPATCHED", ("RESERVED",)),
            ("UNKNOWN", ("DISPATCHED",)),
        ):
            raise ValueError("Unsupported effect transition")
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE shards_effect_operation SET state = %s, updated_at = now()
                           WHERE operation_id = %s AND state = %s
                           RETURNING operation_id""",
                        (target, operation_id, sources[0]),
                    )
                    return cur.fetchone() is not None

    def get(self, operation_id: str) -> EffectOperation | None:
        operation_id = self._identifier(operation_id, "operation_id")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT operation_id, permit_id, request_sha256, state,
                              evidence_ref, provider_ref
                       FROM shards_effect_operation WHERE operation_id = %s""",
                    (operation_id,),
                )
                row = cur.fetchone()
        return EffectOperation(*row) if row is not None else None

    def unresolved(self, limit: int = 100) -> list[EffectOperation]:
        """Return potentially incomplete operations for operator reconciliation."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer between 1 and 1000")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT operation_id, permit_id, request_sha256, state,
                              evidence_ref, provider_ref
                       FROM shards_effect_operation
                       WHERE state IN ('RESERVED', 'DISPATCHED', 'UNKNOWN')
                       ORDER BY updated_at, operation_id LIMIT %s""",
                    (limit,),
                )
                rows = cur.fetchall()
        return [EffectOperation(*row) for row in rows]
