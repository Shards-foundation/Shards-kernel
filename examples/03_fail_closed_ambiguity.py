#!/usr/bin/env python3
"""Example 03: Fail-Closed Ambiguity

Demonstrates how the kernel handles ambiguous requests with fail-closed
semantics.
"""

from shards_kernel.common.types import (
    KernelConfig,
    KernelRequest,
    ToolCall,
    VirtualClock,
)
from shards_kernel.variants.strict_kernel import StrictKernel
from _permit import issue_permit

KEYRING = {"example-key": b"example-secret-key-32bytes-long!"}


def main() -> None:
    """Run fail-closed ambiguity example."""
    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="ambiguity-example-001",
        variant="strict",
        clock=VirtualClock(1000),
    )
    kernel.boot(config)
    kernel.set_keyring(KEYRING)

    print("Fail-Closed Ambiguity Detection")
    print("=" * 50)

    # Test cases demonstrating ambiguity detection
    test_cases = [
        {
            "name": "Empty Intent",
            "request": KernelRequest(
                request_id="req-001",
                ts_ms=1000,
                actor="test-user",
                intent="",  # Empty intent is ambiguous
            ),
        },
        {
            "name": "Whitespace-Only Intent",
            "request": KernelRequest(
                request_id="req-002",
                ts_ms=2000,
                actor="test-user",
                intent="   ",  # Whitespace-only is ambiguous
            ),
        },
        {
            "name": "Tool Call with Empty Name",
            "request": KernelRequest(
                request_id="req-003",
                ts_ms=3000,
                actor="test-user",
                intent="Execute a tool",
                tool_call=ToolCall(name="", params={}),  # Empty tool name
            ),
        },
        {
            "name": "Overly Long Intent",
            "request": KernelRequest(
                request_id="req-004",
                ts_ms=4000,
                actor="test-user",
                intent="x" * 5000,  # Exceeds max_intent_length (4096)
            ),
        },
        {
            "name": "Valid Request (for comparison)",
            "request": KernelRequest(
                request_id="req-005",
                ts_ms=5000,
                actor="test-user",
                intent="A clear, unambiguous intent",
                tool_call=ToolCall(name="echo", params={"text": "test"}),
                params={"text": "test"},
            ),
            "permit": issue_permit(
                KEYRING,
                "example-key",
                subject="test-user",
                action="echo",
                params={"text": "test"},
            ),
        },
    ]

    for case in test_cases:
        print(f"\n[{case['name']}]")
        request = case["request"]
        print(
            f"  Intent: {repr(request.intent[:50])}{'...' if len(request.intent) > 50 else ''}"
        )

        receipt = kernel.submit(request, permit_token=case.get("permit"))

        print(f"  Status: {receipt.status.value}")
        print(f"  Decision: {receipt.decision.value}")
        if receipt.error:
            print(f"  Error: {receipt.error[:80]}...")

    # Demonstrate that kernel remains operational after denials
    print("\n" + "=" * 50)
    print(f"Kernel state after all tests: {kernel.get_state().value}")

    evidence = kernel.export_evidence()
    print(f"Total audit entries: {len(evidence.ledger_entries)}")

    # Count decisions
    allow_count = sum(1 for e in evidence.ledger_entries if e.decision.value == "ALLOW")
    deny_count = sum(1 for e in evidence.ledger_entries if e.decision.value == "DENY")
    print(f"ALLOW decisions: {allow_count}")
    print(f"DENY decisions: {deny_count}")


if __name__ == "__main__":
    main()
