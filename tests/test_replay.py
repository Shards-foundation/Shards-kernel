"""Tests for audit replay verification."""

import unittest

from shards_kernel.common.types import Decision, KernelState
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.audit.replay import replay_and_verify, verify_evidence_bundle


class TestReplay(unittest.TestCase):
    """Test cases for replay verification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.ledger = AuditLedger("test-kernel", "strict")

    def test_empty_ledger_valid(self) -> None:
        """Empty ledger is valid."""
        is_valid, errors = replay_and_verify([])
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_single_entry_valid(self) -> None:
        """Single entry ledger verifies correctly."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entries = self.ledger.to_list()
        is_valid, errors = replay_and_verify(entries)

        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_multi_entry_valid(self) -> None:
        """Multi-entry ledger verifies correctly."""
        for i in range(5):
            self.ledger.append(
                request_id=f"req-{i:03d}",
                actor="alice",
                intent=f"intent {i}",
                decision=Decision.ALLOW,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=1000 + i,
            )

        entries = self.ledger.to_list()
        is_valid, errors = replay_and_verify(entries)

        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_tampered_entry_detected(self) -> None:
        """Tampered entry is detected."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entries = self.ledger.to_list()
        entries[0]["intent"] = "tampered intent"

        is_valid, errors = replay_and_verify(entries)

        self.assertFalse(is_valid)
        self.assertTrue(len(errors) > 0)

    def test_broken_chain_detected(self) -> None:
        """Broken hash chain is detected."""
        for i in range(3):
            self.ledger.append(
                request_id=f"req-{i:03d}",
                actor="alice",
                intent=f"intent {i}",
                decision=Decision.ALLOW,
                state_from=KernelState.IDLE,
                state_to=KernelState.IDLE,
                ts_ms=1000 + i,
            )

        entries = self.ledger.to_list()
        entries[1]["prev_hash"] = "0" * 64  # Break the chain

        is_valid, errors = replay_and_verify(entries)

        self.assertFalse(is_valid)
        self.assertTrue(len(errors) > 0)

    def test_verify_evidence_bundle(self) -> None:
        """Evidence bundle verification works."""
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
        bundle_dict = {
            "ledger_entries": self.ledger.to_list(),
            "root_hash": bundle.root_hash,
            "exported_at_ms": bundle.exported_at_ms,
            "kernel_id": bundle.kernel_id,
            "variant": bundle.variant,
        }

        result = verify_evidence_bundle(bundle_dict)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.entries_verified, 1)
        self.assertEqual(result.errors, [])

    def test_root_hash_mismatch(self) -> None:
        """Root hash mismatch is detected."""
        self.ledger.append(
            request_id="req-001",
            actor="alice",
            intent="test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.IDLE,
            ts_ms=1000,
        )

        entries = self.ledger.to_list()
        is_valid, errors = replay_and_verify(entries, expected_root_hash="wrong_hash")

        self.assertFalse(is_valid)
        self.assertTrue(any("Root hash" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
