"""SQLite persistence backend for KERNELS audit ledger entries."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class SQLiteAuditStorage:
    """Persist and retrieve audit entries in a local SQLite database."""

    def __init__(self, database_path: str) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with SQLite's strongest standard sync setting."""
        connection = sqlite3.connect(self._database_path)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_kernel_metadata (
                    kernel_id TEXT PRIMARY KEY,
                    variant TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    kernel_id TEXT NOT NULL,
                    ledger_seq INTEGER NOT NULL,
                    entry_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    ts_ms INTEGER NOT NULL,
                    request_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    state_from TEXT NOT NULL,
                    state_to TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (kernel_id, ledger_seq)
                )
                """
            )

    def bind_kernel(self, kernel_id: str, variant: str) -> None:
        """Bind a database kernel ID to one variant and reject drift."""
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO audit_kernel_metadata (kernel_id, variant) VALUES (?, ?)",
                (kernel_id, variant),
            )
            row = connection.execute(
                "SELECT variant FROM audit_kernel_metadata WHERE kernel_id = ?",
                (kernel_id,),
            ).fetchone()
        if row is None or row[0] != variant:
            raise ValueError(
                f"Kernel {kernel_id!r} is already bound to a different variant"
            )

    def append(self, kernel_id: str, entry: dict[str, Any]) -> None:
        """Insert a single audit entry row."""
        payload_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_entries (
                    kernel_id, ledger_seq, entry_hash, prev_hash, ts_ms,
                    request_id, actor, intent, decision, state_from, state_to, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kernel_id,
                    int(entry["ledger_seq"]),
                    str(entry["entry_hash"]),
                    str(entry["prev_hash"]),
                    int(entry["ts_ms"]),
                    str(entry["request_id"]),
                    str(entry["actor"]),
                    str(entry["intent"]),
                    str(entry["decision"]),
                    str(entry["state_from"]),
                    str(entry["state_to"]),
                    payload_json,
                ),
            )

    def list_entries(self, kernel_id: str) -> list[dict[str, Any]]:
        """Return all entries for a kernel ordered by ledger sequence."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM audit_entries
                WHERE kernel_id = ?
                ORDER BY ledger_seq ASC
                """,
                (kernel_id,),
            ).fetchall()

        return [json.loads(row[0]) for row in rows]

    def health(self) -> dict[str, Any]:
        """Return health diagnostics for this storage backend."""
        try:
            with self._connect() as connection:
                table_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_entries'"
                ).fetchone()
                entry_count = connection.execute(
                    "SELECT COUNT(1) FROM audit_entries"
                ).fetchone()
        except sqlite3.Error as exc:
            return {
                "ok": False,
                "database_path": str(self._database_path),
                "error": str(exc),
            }

        return {
            "ok": bool(table_exists),
            "database_path": str(self._database_path),
            "entries": int(entry_count[0]) if entry_count else 0,
        }
