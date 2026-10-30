"""Tests for kernel variants."""

import unittest

from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel


def make_config(kernel_id: str, variant: str) -> KernelConfig:
    """Create a test configuration."""
    return KernelConfig(
        kernel_id=kernel_id,
        variant=variant,
        clock=VirtualClock(1000),
    )


class TestStrictKernel(unittest.TestCase):
    """Test cases for StrictKernel."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.kernel = StrictKernel()
        self.kernel.boot(make_config("strict-001", "strict"))

    def test_boot_state(self) -> None:
        """Kernel boots to IDLE state."""
        self.assertEqual(self.kernel.get_state(), KernelState.IDLE)

    def test_unpermitted_tool_call_denied(self) -> None:
        """A tool call without a permit is denied, even with no keyring."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="echo test",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("MISSING_PERMIT", receipt.error or "")
        self.assertIsNone(receipt.tool_result)

    def test_empty_intent_denied(self) -> None:
        """Empty intent is denied."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="",
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)

    def test_halt(self) -> None:
        """Kernel can be halted."""
        receipt = self.kernel.halt("test halt")

        self.assertEqual(self.kernel.get_state(), KernelState.HALTED)
        self.assertEqual(receipt.decision, Decision.HALT)

    def test_export_evidence(self) -> None:
        """Evidence can be exported."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test",
            tool_call=ToolCall(name="echo", params={"text": "hi"}),
        )
        self.kernel.submit(request)

        bundle = self.kernel.export_evidence()

        self.assertEqual(bundle.kernel_id, "strict-001")
        self.assertEqual(len(bundle.ledger_entries), 1)


class TestPermissiveKernel(unittest.TestCase):
    """Test cases for PermissiveKernel."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.kernel = PermissiveKernel()
        self.kernel.boot(make_config("permissive-001", "permissive"))

    def test_intent_only_allowed(self) -> None:
        """Intent-only request is allowed."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="just an intent, no tool",
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.decision, Decision.ALLOW)

    def test_longer_intent_allowed(self) -> None:
        """Longer intents are allowed in permissive mode."""
        long_intent = "x" * 5000  # Longer than strict default

        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent=long_intent,
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)


class TestEvidenceFirstKernel(unittest.TestCase):
    """Test cases for EvidenceFirstKernel."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.kernel = EvidenceFirstKernel()
        self.kernel.boot(make_config("evidence-001", "evidence-first"))

    def test_missing_evidence_denied(self) -> None:
        """Request without evidence is denied."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("Evidence", receipt.error)

    def test_with_evidence_allowed(self) -> None:
        """Request with evidence is allowed."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
            evidence="This is the evidence for this request",
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.decision, Decision.ALLOW)


class TestDualChannelKernel(unittest.TestCase):
    """Test cases for DualChannelKernel."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.kernel = DualChannelKernel()
        self.kernel.boot(make_config("dual-001", "dual-channel"))

    def test_missing_constraints_denied(self) -> None:
        """Request without constraints is denied."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
            params={},
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)
        self.assertIn("constraints", receipt.error.lower())

    def test_partial_constraints_denied(self) -> None:
        """Request with partial constraints is denied."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
            params={
                "constraints": {
                    "scope": "test scope",
                    # Missing non_goals and success_criteria
                }
            },
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.REJECTED)
        self.assertEqual(receipt.decision, Decision.DENY)

    def test_full_constraints_allowed(self) -> None:
        """Request with full constraints is allowed."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
            params={
                "constraints": {
                    "scope": "test scope",
                    "non_goals": "things we will not do",
                    "success_criteria": "how we measure success",
                }
            },
        )

        receipt = self.kernel.submit(request)

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt.decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
