"""Tests for the standalone SQLite evidence storage helper."""

import tempfile
import unittest
from pathlib import Path

from implementations.storage import SQLiteAuditStorage


class TestSQLiteAuditStorage(unittest.TestCase):
    def test_entries_survive_reopening_storage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "audit.sqlite3")
            storage = SQLiteAuditStorage(database)
            entry = {
                "ledger_seq": 0,
                "entry_hash": "entry-hash",
                "prev_hash": "genesis",
                "ts_ms": 1000,
                "request_id": "req-1",
                "actor": "operator",
                "intent": "test persistence",
                "decision": "ALLOW",
                "state_from": "IDLE",
                "state_to": "IDLE",
            }
            storage.append("kernel-1", entry)

            reopened = SQLiteAuditStorage(database)
            self.assertEqual(reopened.list_entries("kernel-1"), [entry])
            self.assertTrue(reopened.health()["ok"])
            self.assertEqual(reopened.health()["entries"], 1)

    def test_entries_are_scoped_by_kernel_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            storage = SQLiteAuditStorage(str(Path(directory) / "audit.sqlite3"))
            entry = {
                "ledger_seq": 0,
                "entry_hash": "entry-hash",
                "prev_hash": "genesis",
                "ts_ms": 1000,
                "request_id": "req-1",
                "actor": "operator",
                "intent": "test isolation",
                "decision": "DENY",
                "state_from": "IDLE",
                "state_to": "IDLE",
            }
            storage.append("kernel-a", entry)

            self.assertEqual(storage.list_entries("kernel-a"), [entry])
            self.assertEqual(storage.list_entries("kernel-b"), [])


if __name__ == "__main__":
    unittest.main()
