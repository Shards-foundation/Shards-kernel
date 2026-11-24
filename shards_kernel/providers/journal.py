"""Durable, append-only intent/effect journal for trusted providers.

The journal is committed **before** a provider request is dispatched and
again **after** the authoritative outcome is known. It deliberately has no
automatic retry: a ``DISPATCHED`` or ``UNKNOWN`` operation is reconciled by
read-back only, never by re-sending the effect.

The journal is a local SQLite database with ``synchronous=FULL``. It is a
single-host durability record, not a distributed consensus store.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from shards_kernel.common.time import SystemClock

INTENT = "INTENT"
DISPATCHED = "DISPATCHED"
SUCCEEDED = "SUCCEEDED"
NOT_APPLIED = "NOT_APPLIED"
UNKNOWN = "UNKNOWN"

TERMINAL_STATES = frozenset({SUCCEEDED, NOT_APPLIED})
OPEN_STATES = frozenset({INTENT, DISPATCHED, UNKNOWN})
OUTCOME_STATES = frozenset({SUCCEEDED, NOT_APPLIED, UNKNOWN})
ALL_STATES = frozenset({INTENT, DISPATCHED, SUCCEEDED, NOT_APPLIED, UNKNOWN})
_ALLOWED_OUTCOME_TRANSITIONS = {
    INTENT: OUTCOME_STATES,
    DISPATCHED: OUTCOME_STATES,
    UNKNOWN: frozenset({SUCCEEDED, NOT_APPLIED, UNKNOWN}),
}

_MAX_IDENTIFIER = 200
_MAX_DETAIL = 500


class ProviderJournalError(RuntimeError):
    """A journal invariant or durable write failed. Callers must fail closed."""


def _bounded(value: Any, label: str, limit: int = _MAX_IDENTIFIER) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or not value.isascii()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError(f"{label} must be a bounded printable ASCII string")
    return value


def _safe_detail(value: Optional[str]) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch for ch in value if 32 <= ord(ch) < 127)
    return cleaned[:_MAX_DETAIL]


def _safe_reference(value: str) -> str:
    """Allow an empty reference, but never persist control or non-ASCII bytes."""
    if (
        not isinstance(value, str)
        or len(value) > _MAX_IDENTIFIER
        or not value.isascii()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError("provider_ref must be a bounded printable ASCII string")
    return value


@dataclass(frozen=True)
class ProviderEffectRecord:
    """One durable provider operation and its last committed state."""

    operation_id: str
    provider: str
    resource: str
    action: str
    params_sha256: str
    request_id: str
    permit_id: str
    state: str
    attempts: int
    created_ms: int
    updated_ms: int
    provider_ref: str
    detail: str


class ProviderEffectJournal:
    """SQLite-backed intent/effect journal for one trusted provider."""

    def __init__(self, database_path: str | os.PathLike[str], *, clock: Any = None) -> None:
        path = Path(database_path)
        if not path.is_absolute():
            raise ValueError("Provider journal path must be absolute")
        if path.is_symlink() or path.is_dir():
            raise ValueError("Provider journal must be a regular non-symlink file")
        if not path.parent.is_dir():
            raise ValueError("Provider journal parent directory must exist")
        self._path = path
        self._clock = clock or SystemClock()
        self._initialize()

    def _now_ms(self) -> int:
        value = self._clock.now_ms()
        if type(value) is not int or value < 0:
            raise ProviderJournalError("JOURNAL_CLOCK_INVALID")
        return value

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self._path), timeout=5.0, isolation_level=None
        )
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        try:
            with contextlib.closing(self._connect()) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS provider_effect_journal (
                        operation_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        action TEXT NOT NULL,
                        params_sha256 TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        permit_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        attempts INTEGER NOT NULL,
                        created_ms INTEGER NOT NULL,
                        updated_ms INTEGER NOT NULL,
                        provider_ref TEXT NOT NULL,
                        detail TEXT NOT NULL
                    )
                    """
                )
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        """Release journal resources.

        Connections are opened per operation and closed in each method, so this
        is a stable shutdown hook rather than a cached-connection close.
        """

    def _row_to_record(self, row: tuple[Any, ...]) -> ProviderEffectRecord:
        return ProviderEffectRecord(
            operation_id=str(row[0]),
            provider=str(row[1]),
            resource=str(row[2]),
            action=str(row[3]),
            params_sha256=str(row[4]),
            request_id=str(row[5]),
            permit_id=str(row[6]),
            state=str(row[7]),
            attempts=int(row[8]),
            created_ms=int(row[9]),
            updated_ms=int(row[10]),
            provider_ref=str(row[11]),
            detail=str(row[12]),
        )

    def _select(
        self, connection: sqlite3.Connection, operation_id: str
    ) -> Optional[ProviderEffectRecord]:
        row = connection.execute(
            """
            SELECT operation_id, provider, resource, action, params_sha256,
                   request_id, permit_id, state, attempts, created_ms,
                   updated_ms, provider_ref, detail
            FROM provider_effect_journal
            WHERE operation_id = ?
            """,
            (operation_id,),
        ).fetchone()
        return None if row is None else self._row_to_record(row)

    def get(self, operation_id: str) -> Optional[ProviderEffectRecord]:
        """Return the committed record, if any."""
        _bounded(operation_id, "operation_id")
        try:
            with contextlib.closing(self._connect()) as connection:
                return self._select(connection, operation_id)
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc

    def reserve(
        self,
        *,
        operation_id: str,
        provider: str,
        resource: str,
        action: str,
        params_sha256: str,
        request_id: str,
        permit_id: str,
    ) -> ProviderEffectRecord:
        """Commit an INTENT before any provider request is sent.

        An existing record is returned unchanged. The caller decides whether
        its state permits dispatch; this method never overwrites state.
        """
        _bounded(operation_id, "operation_id")
        _bounded(provider, "provider")
        _bounded(resource, "resource")
        _bounded(action, "action")
        _bounded(params_sha256, "params_sha256")
        _bounded(request_id, "request_id")
        _bounded(permit_id, "permit_id")
        now = self._now_ms()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._select(connection, operation_id)
                if existing is not None:
                    if (
                        existing.provider != provider
                        or existing.resource != resource
                        or existing.action != action
                        or existing.params_sha256 != params_sha256
                        or existing.request_id != request_id
                        or existing.permit_id != permit_id
                    ):
                        connection.execute("ROLLBACK")
                        raise ProviderJournalError("JOURNAL_OPERATION_CONFLICT")
                    connection.execute("COMMIT")
                    return existing
                connection.execute(
                    """
                    INSERT INTO provider_effect_journal (
                        operation_id, provider, resource, action, params_sha256,
                        request_id, permit_id, state, attempts, created_ms,
                        updated_ms, provider_ref, detail
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, '', '')
                    """,
                    (
                        operation_id, provider, resource, action, params_sha256,
                        request_id, permit_id, INTENT, now, now,
                    ),
                )
                record = self._select(connection, operation_id)
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc
        if record is None:
            raise ProviderJournalError("JOURNAL_WRITE_NOT_VISIBLE")
        return record

    def mark_dispatched(self, operation_id: str) -> ProviderEffectRecord:
        """Commit DISPATCHED immediately before the provider request is sent."""
        _bounded(operation_id, "operation_id")
        now = self._now_ms()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE provider_effect_journal
                    SET state = ?, attempts = attempts + 1, updated_ms = ?
                    WHERE operation_id = ? AND state = ?
                    """,
                    (DISPATCHED, now, operation_id, INTENT),
                )
                if cursor.rowcount != 1:
                    connection.execute("ROLLBACK")
                    raise ProviderJournalError("JOURNAL_STATE_CONFLICT")
                record = self._select(connection, operation_id)
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc
        if record is None:
            raise ProviderJournalError("JOURNAL_WRITE_NOT_VISIBLE")
        return record

    def record_outcome(
        self,
        operation_id: str,
        state: str,
        *,
        provider_ref: str = "",
        detail: str = "",
        expected_provider: Optional[str] = None,
        expected_resource: Optional[str] = None,
        expected_action: Optional[str] = None,
        expected_params_sha256: Optional[str] = None,
        expected_request_id: Optional[str] = None,
        expected_permit_id: Optional[str] = None,
    ) -> ProviderEffectRecord:
        """Commit a terminal outcome (or preserve a quarantine as UNKNOWN).

        ``UNKNOWN`` may later be reconciled to ``SUCCEEDED`` or
        ``NOT_APPLIED`` by authoritative read-back. ``INTENT`` and
        ``DISPATCHED`` are never valid outcome states, so a quarantine cannot
        regress to a non-terminal state. Terminal states are final.

        Optional ``expected_*`` values bind the outcome to the existing
        operation's immutable provider/resource/action/params/request/permit.
        A mismatch fails closed instead of reporting another operation's effect.
        """
        _bounded(operation_id, "operation_id")
        if state not in OUTCOME_STATES:
            raise ValueError("Unsupported provider journal outcome state")
        safe_reference = _safe_reference(provider_ref)
        for value, label in (
            (expected_provider, "expected_provider"),
            (expected_resource, "expected_resource"),
            (expected_action, "expected_action"),
            (expected_params_sha256, "expected_params_sha256"),
            (expected_request_id, "expected_request_id"),
            (expected_permit_id, "expected_permit_id"),
        ):
            if value is not None:
                _bounded(value, label)
        safe_detail = _safe_detail(detail)
        now = self._now_ms()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._select(connection, operation_id)
                if existing is None:
                    connection.execute("ROLLBACK")
                    raise ProviderJournalError("JOURNAL_OPERATION_MISSING")
                if any(
                    expected is not None and actual != expected
                    for actual, expected in (
                        (existing.provider, expected_provider),
                        (existing.resource, expected_resource),
                        (existing.action, expected_action),
                        (existing.params_sha256, expected_params_sha256),
                        (existing.request_id, expected_request_id),
                        (existing.permit_id, expected_permit_id),
                    )
                ):
                    connection.execute("ROLLBACK")
                    raise ProviderJournalError("JOURNAL_OPERATION_CONFLICT")
                if existing.state == state:
                    connection.execute("COMMIT")
                    return existing
                if state not in _ALLOWED_OUTCOME_TRANSITIONS.get(
                    existing.state, frozenset()
                ):
                    connection.execute("ROLLBACK")
                    raise ProviderJournalError("JOURNAL_STATE_CONFLICT")
                cursor = connection.execute(
                    """
                    UPDATE provider_effect_journal
                    SET state = ?, provider_ref = ?, detail = ?, updated_ms = ?
                    WHERE operation_id = ? AND state = ?
                    """,
                    (
                        state, safe_reference, safe_detail, now, operation_id,
                        existing.state,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.execute("ROLLBACK")
                    raise ProviderJournalError("JOURNAL_STATE_CONFLICT")
                record = self._select(connection, operation_id)
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    # Preserve the original failure; a rollback failure is
                    # secondary and must not mask it.
                    pass
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc
        if record is None:
            raise ProviderJournalError("JOURNAL_WRITE_NOT_VISIBLE")
        return record

    def open_operations(self) -> tuple[ProviderEffectRecord, ...]:
        """Return INTENT/DISPATCHED/UNKNOWN operations requiring reconciliation."""
        try:
            with contextlib.closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT operation_id, provider, resource, action, params_sha256,
                           request_id, permit_id, state, attempts, created_ms,
                           updated_ms, provider_ref, detail
                    FROM provider_effect_journal
                    WHERE state IN (?, ?, ?)
                    ORDER BY created_ms ASC, operation_id ASC
                    """,
                    (INTENT, DISPATCHED, UNKNOWN),
                ).fetchall()
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc
        return tuple(self._row_to_record(row) for row in rows)

    def count_by_state(self) -> dict[str, int]:
        """Return a diagnostic count per state. Never contains credentials."""
        try:
            with contextlib.closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT state, COUNT(1) FROM provider_effect_journal GROUP BY state"
                ).fetchall()
        except sqlite3.Error as exc:
            raise ProviderJournalError("JOURNAL_UNAVAILABLE") from exc
        counts = {state: 0 for state in ALL_STATES}
        for state, count in rows:
            counts[str(state)] = int(count)
        return counts
