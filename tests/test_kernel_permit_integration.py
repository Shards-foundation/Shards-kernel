"""
Integration tests for permit token enforcement in kernel lifecycle.

These tests verify that:
1. No execution occurs without verified permit
2. Permit verification is audited
3. Replay protection works across kernel restarts
4. Variant-specific permit policies are enforced
"""

import unittest
from dataclasses import replace

from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel


class TestPermitIntegrationHappyPath(unittest.TestCase):
    """Test happy path: valid permit → execution → audit."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.clock = VirtualClock(initial_ms=1000)
        self.config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=self.clock,
        )
        self.kernel = StrictKernel()
        self.kernel.boot(self.config)

        # Set up HMAC keyring
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

        # Configure kernel with keyring
        self.kernel.set_keyring(self.keyring)

    def test_valid_permit_reaches_execution(self) -> None:
        """Valid permit allows execution and creates audit trail."""
        # Build permit
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("evidence-hash-123")
            .proposal_hash("proposal-hash-456")
            .build(self.keyring, "key1")
        )

        # Create request with permit
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello world",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # Submit with permit
        receipt = self.kernel.submit(request, permit_token=permit)

        # Assert: Execution succeeded
        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.decision, Decision.ALLOW)
        self.assertIsNotNone(receipt.tool_result)

        # Assert: Audit contains an intent record and an outcome record.
        evidence = self.kernel.export_evidence()
        entries = evidence.ledger_entries
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].audit_phase, "intent")
        self.assertEqual(entries[0].permit_verification, "INTENT")
        entry = entries[1]
        self.assertEqual(entry.audit_phase, "outcome")
        self.assertEqual(entry.decision, Decision.ALLOW)
        self.assertEqual(entry.permit_digest, permit.permit_id)
        self.assertEqual(entry.permit_verification, "OUTCOME")
        self.assertEqual(len(entry.permit_denial_reasons), 0)
        self.assertEqual(entry.proposal_hash, permit.proposal_hash)


class TestPermitIntegrationMissingPermit(unittest.TestCase):
    """Test missing permit denial."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.clock = VirtualClock(initial_ms=1000)
        self.config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=self.clock,
        )
        self.kernel = StrictKernel()
        self.kernel.boot(self.config)

        # Set up keyring so permits are required
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}
        self.kernel.set_keyring(self.keyring)

    def test_missing_permit_denied_in_validating(self) -> None:
        """Missing permit (when required) denies in VALIDATING."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello world",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # Submit WITHOUT permit (permit_token=None)
        receipt = self.kernel.submit(request, permit_token=None)

        # Assert: Request denied
        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("MISSING_PERMIT", receipt.error)

        # Assert: No execution occurred
        self.assertIsNone(receipt.tool_result)

        # Assert: Denial audited
        evidence = self.kernel.export_evidence()
        entries = evidence.ledger_entries
        self.assertEqual(len(entries), 1)

        entry = entries[0]
        self.assertEqual(entry.decision, Decision.DENY)
        self.assertIn("MISSING_PERMIT", entry.error)


class TestPermitIntegrationMismatch(unittest.TestCase):
    """Test permit-tool mismatch denial."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.clock = VirtualClock(initial_ms=1000)
        self.config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=self.clock,
        )
        self.kernel = StrictKernel()
        self.kernel.boot(self.config)

        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

        # Configure kernel with keyring
        self.kernel.set_keyring(self.keyring)

    def test_permit_tool_mismatch_denied(self) -> None:
        """Permit authorizes tool A, request uses tool B → deny."""
        # Build permit for "echo"
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")  # Permit authorizes "echo"
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        # Create request for "add" (different tool)
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Add numbers",
            tool_call=ToolCall(name="add", params={"a": 1, "b": 2}),  # Different tool
            params={"a": 1, "b": 2},
        )

        # Submit with mismatched permit
        receipt = self.kernel.submit(request, permit_token=permit)

        # Assert: Request denied due to action mismatch
        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        # The error should mention either ACTION_NOT_ALLOWED or similar
        self.assertIsNotNone(receipt.error)

        # Assert: Audit shows permit denial
        evidence = self.kernel.export_evidence()
        entries = evidence.ledger_entries
        entry = entries[0]
        self.assertEqual(entry.decision, Decision.DENY)
        self.assertEqual(entry.permit_verification, "DENY")
        self.assertGreater(len(entry.permit_denial_reasons), 0)


class TestPermitIntegrationReplay(unittest.TestCase):
    """Test replay protection across lifecycle."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.clock = VirtualClock(initial_ms=1000)
        self.config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=self.clock,
        )
        self.kernel = StrictKernel()
        self.kernel.boot(self.config)

        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

        # Configure kernel with keyring
        self.kernel.set_keyring(self.keyring)

    def test_single_use_permit_replay_denied(self) -> None:
        """Single-use permit: first use allowed, second denied."""
        # Build single-use permit
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)  # Single-use
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # First use: should succeed
        receipt1 = self.kernel.submit(request, permit_token=permit)
        self.assertEqual(receipt1.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt1.decision, Decision.ALLOW)

        # Advance clock
        self.clock.advance(1000)

        # Second use (replay): should be denied
        request2 = replace(request, request_id="req-002", ts_ms=2000)
        receipt2 = self.kernel.submit(request2, permit_token=permit)

        # Assert: Replay denied
        self.assertEqual(receipt2.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt2.decision, Decision.DENY)

        # Assert: Audit shows replay detection after the intent and outcome.
        evidence = self.kernel.export_evidence()
        entries = evidence.ledger_entries
        self.assertEqual(len(entries), 3)

        # Last entry should show replay denial
        entry2 = entries[-1]
        self.assertEqual(entry2.decision, Decision.DENY)
        self.assertIn("REPLAY_DETECTED", entry2.permit_denial_reasons)


class TestPermitIntegrationCrossRestart(unittest.TestCase):
    """Test ledger-backed replay protection across restarts."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

    def test_replay_detected_after_restart(self) -> None:
        """Nonce registry rebuilt from ledger prevents replay after restart."""
        clock = VirtualClock(initial_ms=1000)
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=clock,
        )

        # First kernel instance
        kernel1 = StrictKernel()
        kernel1.boot(config)
        kernel1.set_keyring(self.keyring)

        # Build permit
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # Use permit in first instance
        receipt1 = kernel1.submit(request, permit_token=permit)
        self.assertEqual(receipt1.decision, Decision.ALLOW)

        # Export ledger
        evidence1 = kernel1.export_evidence()

        # Simulate restart: create new kernel instance with same ledger
        kernel2 = StrictKernel()
        kernel2.boot(config)
        kernel2.set_keyring(self.keyring)
        kernel2.load_ledger(evidence1)  # Restore from exported ledger

        # Try to replay permit in second instance
        clock.advance(1000)
        request2 = replace(request, request_id="req-002", ts_ms=2000)
        receipt2 = kernel2.submit(request2, permit_token=permit)

        # Assert: Replay detected after restart
        self.assertEqual(receipt2.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt2.decision, Decision.DENY)

        # Verify nonce was tracked across restart
        evidence2 = kernel2.export_evidence()
        final_entry = evidence2.ledger_entries[-1]
        self.assertIn("REPLAY_DETECTED", final_entry.permit_denial_reasons)

    def test_multi_use_permit_across_restart_max_three(self) -> None:
        """Multi-use permit (N=3): use twice, restart, use once more succeeds, fourth fails."""
        clock = VirtualClock(initial_ms=1000)
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=clock,
        )

        # First kernel instance
        kernel1 = StrictKernel()
        kernel1.boot(config)
        kernel1.set_keyring(self.keyring)

        # Build multi-use permit (max_executions=3)
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(3)  # Allow 3 uses
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        # Use 1: Should succeed
        request1 = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        receipt1 = kernel1.submit(request1, permit_token=permit)
        self.assertEqual(receipt1.decision, Decision.ALLOW)

        # Use 2: Should succeed
        clock.advance(100)
        request2 = replace(request1, request_id="req-002", ts_ms=1100)
        receipt2 = kernel1.submit(request2, permit_token=permit)
        self.assertEqual(receipt2.decision, Decision.ALLOW)

        # Export ledger and restart
        evidence1 = kernel1.export_evidence()

        # Second kernel instance with ledger restoration
        kernel2 = StrictKernel()
        kernel2.boot(config)
        kernel2.set_keyring(self.keyring)
        kernel2.load_ledger(evidence1)

        # Use 3: Should succeed (within max_executions=3)
        clock.advance(100)
        request3 = replace(request1, request_id="req-003", ts_ms=1200)
        receipt3 = kernel2.submit(request3, permit_token=permit)
        self.assertEqual(receipt3.decision, Decision.ALLOW)

        # Use 4: Should fail (exceeded max_executions=3)
        clock.advance(100)
        request4 = replace(request1, request_id="req-004", ts_ms=1300)
        receipt4 = kernel2.submit(request4, permit_token=permit)
        self.assertEqual(receipt4.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt4.decision, Decision.DENY)

        # Verify final ledger state. Each successful use writes an intent
        # record and an outcome record; the denial writes one outcome.
        evidence2 = kernel2.export_evidence()
        decisions = [entry.decision for entry in evidence2.ledger_entries]
        self.assertEqual(
            decisions,
            [
                Decision.ALLOW,
                Decision.ALLOW,
                Decision.ALLOW,
                Decision.ALLOW,
                Decision.ALLOW,
                Decision.ALLOW,
                Decision.DENY,
            ],
        )
        self.assertIn(
            "REPLAY_DETECTED", evidence2.ledger_entries[-1].permit_denial_reasons
        )

    def test_multi_use_permit_use_count_reconstruction(self) -> None:
        """Verify use_count is correctly reconstructed from ledger."""
        clock = VirtualClock(initial_ms=1000)
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=clock,
        )

        # First kernel instance
        kernel1 = StrictKernel()
        kernel1.boot(config)
        kernel1.set_keyring(self.keyring)

        # Build multi-use permit (max_executions=5)
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(5)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        # Use permit 3 times in first instance
        for i in range(3):
            clock.advance(100)
            request = KernelRequest(
                request_id=f"req-{i:03d}",
                ts_ms=clock.now_ms(),
                actor="agent1",
                intent="Echo hello",
                tool_call=ToolCall(name="echo", params={"text": "hello"}),
                params={"text": "hello"},
            )
            receipt = kernel1.submit(request, permit_token=permit)
            self.assertEqual(
                receipt.decision, Decision.ALLOW, f"Use {i + 1} should succeed"
            )

        # Export and restart
        evidence1 = kernel1.export_evidence()
        kernel2 = StrictKernel()
        kernel2.boot(config)
        kernel2.set_keyring(self.keyring)
        kernel2.load_ledger(evidence1)

        # Verify nonce registry was reconstructed with correct use_count
        nonce_record = kernel2._nonce_registry.get_record(
            nonce=permit.nonce,
            issuer=permit.issuer,
            subject=permit.subject,
        )
        self.assertIsNotNone(nonce_record)
        self.assertEqual(
            nonce_record.use_count, 3, "use_count should be reconstructed as 3"
        )

        # Use permit 2 more times (should both succeed, reaching max_executions=5)
        for i in range(3, 5):
            clock.advance(100)
            request = KernelRequest(
                request_id=f"req-{i:03d}",
                ts_ms=clock.now_ms(),
                actor="agent1",
                intent="Echo hello",
                tool_call=ToolCall(name="echo", params={"text": "hello"}),
                params={"text": "hello"},
            )
            receipt = kernel2.submit(request, permit_token=permit)
            self.assertEqual(
                receipt.decision, Decision.ALLOW, f"Use {i + 1} should succeed"
            )

        # Sixth use should fail
        clock.advance(100)
        request_final = KernelRequest(
            request_id="req-final",
            ts_ms=clock.now_ms(),
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )
        receipt_final = kernel2.submit(request_final, permit_token=permit)
        self.assertEqual(receipt_final.decision, Decision.DENY)

        # Verify REPLAY_DETECTED in audit
        evidence_final = kernel2.export_evidence()
        final_entry = evidence_final.ledger_entries[-1]
        self.assertIn("REPLAY_DETECTED", final_entry.permit_denial_reasons)


class TestPermitIntegrationVariantSpecific(unittest.TestCase):
    """Test variant-specific permit policies."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.clock = VirtualClock(initial_ms=1000)
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

    def test_strict_kernel_escalates_to_halt(self) -> None:
        """StrictKernel halts on malformed permit (if policy defined)."""
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="strict",
            clock=self.clock,
        )
        kernel = StrictKernel()
        kernel.boot(config)
        kernel.set_keyring(self.keyring)  # Set keyring to enable permit enforcement

        # Create permit with tampered signature
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        # Tamper with signature
        tampered_permit = replace(permit, signature="0" * 64)

        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # Submit with tampered permit
        receipt = kernel.submit(request, permit_token=tampered_permit)

        # Assert: Denied (or halted, depending on policy)
        # For now, we expect DENY with SIGNATURE_INVALID
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIsNotNone(receipt.error)

    def test_permissive_kernel_allows_no_permit_for_dry_run(self) -> None:
        """PermissiveKernel allows permit=None for intent-only requests."""
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="permissive",
            clock=self.clock,
        )
        kernel = PermissiveKernel()
        kernel.boot(config)
        kernel.set_keyring(self.keyring)

        # Intent-only request (no tool_call)
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Dry run test",
            tool_call=None,  # No tool call = no execution
        )

        # Submit without permit
        receipt = kernel.submit(request, permit_token=None)

        # Assert: Allowed (because no execution happens)
        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.decision, Decision.ALLOW)

    def test_evidence_first_kernel_requires_evidence_in_permit(self) -> None:
        """EvidenceFirstKernel requires non-empty evidence_hash in permit."""
        config = KernelConfig(
            kernel_id="test-kernel",
            variant="evidence-first",
            clock=self.clock,
        )
        kernel = EvidenceFirstKernel()
        kernel.boot(config)
        kernel.set_keyring(self.keyring)

        # Build permit WITHOUT evidence_hash
        builder = PermitBuilder()
        permit_no_evidence = (
            builder.issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")  # Empty evidence
            .proposal_hash("proposal-hash")
            .build(self.keyring, "key1")
        )

        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        # Submit with permit lacking evidence
        receipt = kernel.submit(request, permit_token=permit_no_evidence)

        # Assert: Denied due to missing evidence
        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        # Error should mention evidence requirement
        self.assertIsNotNone(receipt.error)


if __name__ == "__main__":
    unittest.main()
