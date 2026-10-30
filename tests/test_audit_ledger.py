"""Tests for audit ledger."""

import unittest

from shards_kernel.common.types import Decision, KernelState
from shards_kernel.common.hashing import genesis_hash
from shards_kernel.audit.ledger import AuditLedger


class TestAuditLedger(unittest.TestCase):
    """Test cases for AuditLedger."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.ledger = AuditLedger("test-kernel", "strict")

    def test_initial_state(self) -> None:
        """New ledger is empty with genesis hash."""
        self.assertEqual(self.ledger.length, 0)
        self.assertEqual(self.ledger.root_hash, genesis_hash())
        self.assertEqual(self.ledger.entries, ())

    def test_append_entry(self) -> None:
        """Appending entry updates ledger state."""
        entry = self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test intent",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        self.assertEqual(self.ledger.length, 1)
        self.assertNotEqual(self.ledger.root_hash, genesis_hash())
        self.assertEqual(entry.request_id, "req-001")
        self.assertEqual(entry.prev_hash, genesis_hash())

    def test_hash_chain(self) -> None:
        """Entries are hash-chained correctly."""
        entry1 = self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="first",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entry2 = self.ledger.append(
            request_id="req-002",
            actor="alice",
            intent="second",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=2000,
        )

        self.assertEqual(entry2.prev_hash, entry1.entry_hash)
        self.assertEqual(self.ledger.root_hash, entry2.entry_hash)

    def test_entries_immutable(self) -> None:
        """Entries tuple is immutable."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entries = self.ledger.entries
        self.assertIsInstance(entries, tuple)

    def test_export(self) -> None:
        """Export produces valid evidence bundle."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        bundle = self.ledger.export(2000)

        self.assertEqual(bundle.kernel_id, "test-kernel")
        self.assertEqual(bundle.variant, "strict")
        self.assertEqual(bundle.exported_at_ms, 2000)
        self.assertEqual(bundle.root_hash, self.ledger.root_hash)
        self.assertEqual(len(bundle.ledger_entries), 1)

    def test_to_list(self) -> None:
        """to_list produces serializable output."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entries_list = self.ledger.to_list()

        self.assertEqual(len(entries_list), 1)
        self.assertIsInstance(entries_list[0], dict)
        self.assertEqual(entries_list[0]["request_id"], "req-001")

    def test_deterministic_hashing(self) -> None:
        """Same inputs produce same hashes."""
        ledger1 = AuditLedger("kernel-1", "strict")
        ledger2 = AuditLedger("kernel-1", "strict")

        ledger1.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        ledger2.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        self.assertEqual(ledger1.root_hash, ledger2.root_hash)


if __name__ == "__main__":
    unittest.main()
