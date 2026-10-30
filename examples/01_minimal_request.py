#!/usr/bin/env python3
"""Example 01: Minimal Request

Demonstrates the basic request/receipt cycle with a strict kernel.
"""

from shards_kernel.common.types import (
    KernelConfig,
    KernelRequest,
    VirtualClock,
)
from shards_kernel.variants.strict_kernel import StrictKernel


def main() -> None:
    """Run minimal request example."""
    # Create and boot kernel
    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="example-kernel-001",
        variant="strict",
        clock=VirtualClock(1000),
    )
    kernel.boot(config)

    print(f"Kernel booted. State: {kernel.get_state().value}")

    # Submit a minimal request (intent only, no tool call)
    request = KernelRequest(
        request_id="req-001",
        ts_ms=1000,
        actor="example-user",
        intent="Demonstrate minimal request handling",
    )

    print(f"\nSubmitting request: {request.request_id}")
    print(f"  Actor: {request.actor}")
    print(f"  Intent: {request.intent}")

    receipt = kernel.submit(request)

    print("\nReceipt received:")
    print(f"  Status: {receipt.status.value}")
    print(f"  Decision: {receipt.decision.value}")
    print(f"  State transition: {receipt.state_from.value} -> {receipt.state_to.value}")
    print(f"  Evidence hash: {receipt.evidence_hash[:16]}...")

    # Export evidence
    evidence = kernel.export_evidence()
    print("\nEvidence bundle:")
    print(f"  Kernel ID: {evidence.kernel_id}")
    print(f"  Variant: {evidence.variant}")
    print(f"  Entries: {len(evidence.ledger_entries)}")
    print(f"  Root hash: {evidence.root_hash[:16]}...")


if __name__ == "__main__":
    main()
