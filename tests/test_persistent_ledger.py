"""Integration tests for durable audit-ledger storage."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from implementations.storage import SQLiteAuditStorage
from kernels.common.errors import AuditError
from kernels.common.types import Decision, KernelState
from kernels.audit.ledger import AuditLedger
from kernels.common.hashing import genesis_hash
from kernels.common.types import KernelConfig, KernelRequest, VirtualClock
from kernels.variants.strict_kernel import StrictKernel


class TestPersistentAuditLedger(unittest.TestCase):
    def test_ledger_restores_verified_entries_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "audit.sqlite3")
            first = AuditLedger(
                "persistent-kernel",
                "strict",
                storage=SQLiteAuditStorage(database),
            )
            first.append(
                request_id="req-1",
                actor="operator",
                intent="persist before continuing",
                decision=Decision.ALLOW,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=1000,
                audit_phase="intent",
            )

            reopened = AuditLedger(
                "persistent-kernel",
                "strict",
                storage=SQLiteAuditStorage(database),
            )
            self.assertEqual(reopened.entries, first.entries)
            self.assertEqual(reopened.root_hash, first.root_hash)
            self.assertEqual(reopened.length, 1)

    def test_storage_failure_does_not_mutate_live_ledger(self) -> None:
        class FailingStorage:
            def bind_kernel(self, kernel_id: str, variant: str) -> None:
                return None

            def list_entries(self, kernel_id: str) -> list[dict[str, object]]:
                return []

            def append(self, kernel_id: str, entry: dict[str, object]) -> None:
                raise OSError("simulated durable storage failure")

        ledger = AuditLedger("fail-closed-kernel", "strict", storage=FailingStorage())
        with self.assertRaises(AuditError):
            ledger.append(
                request_id="req-fail",
                actor="operator",
                intent="must not proceed",
                decision=Decision.ALLOW,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=1000,
            )
        self.assertEqual(ledger.length, 0)
        self.assertEqual(ledger.root_hash, genesis_hash())

    def test_tampered_persisted_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "audit.sqlite3")
            ledger = AuditLedger(
                "tamper-kernel",
                "strict",
                storage=SQLiteAuditStorage(database),
            )
            ledger.append(
                request_id="req-tamper",
                actor="operator",
                intent="original intent",
                decision=Decision.ALLOW,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=1000,
            )

            with sqlite3.connect(database) as connection:
                row = connection.execute(
                    "SELECT payload_json FROM audit_entries WHERE kernel_id = ?",
                    ("tamper-kernel",),
                ).fetchone()
                payload = json.loads(row[0])
                payload["intent"] = "tampered intent"
                connection.execute(
                    "UPDATE audit_entries SET payload_json = ? WHERE kernel_id = ?",
                    (
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        "tamper-kernel",
                    ),
                )

            with self.assertRaises(AuditError):
                AuditLedger(
                    "tamper-kernel",
                    "strict",
                    storage=SQLiteAuditStorage(database),
                )

    def test_database_rejects_variant_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "audit.sqlite3")
            AuditLedger("same-kernel", "strict", storage=SQLiteAuditStorage(database))
            with self.assertRaises(AuditError):
                AuditLedger(
                    "same-kernel",
                    "permissive",
                    storage=SQLiteAuditStorage(database),
                )

    def test_kernel_restores_persistent_ledger_on_boot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "kernel.sqlite3")
            first = StrictKernel(audit_storage=SQLiteAuditStorage(database))
            first.boot(
                KernelConfig(
                    kernel_id="kernel-restart",
                    variant="strict",
                    clock=VirtualClock(1000),
                )
            )
            first.submit(
                KernelRequest(
                    request_id="req-restart",
                    ts_ms=1000,
                    actor="operator",
                    intent="persist this request",
                )
            )
            before = first.export_evidence()

            restarted = StrictKernel(audit_storage=SQLiteAuditStorage(database))
            restarted.boot(
                KernelConfig(
                    kernel_id="kernel-restart",
                    variant="strict",
                    clock=VirtualClock(2000),
                )
            )
            after = restarted.export_evidence()
            self.assertEqual(after.ledger_entries, before.ledger_entries)
            self.assertEqual(after.root_hash, before.root_hash)


if __name__ == "__main__":
    unittest.main()
