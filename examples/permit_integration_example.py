"""
End-to-end example: Using permit tokens with KERNELS.

This example demonstrates:
1. Setting up a kernel with permit verification
2. Creating a permit token
3. Submitting a request with the permit
4. Extracting audit evidence
"""

from kernels.api import (
    KernelConfig,
    KernelRequest,
    PermitBuilder,
    StrictKernel,
    ToolCall,
    VirtualClock,
)


def main() -> None:
    """Run permit integration example."""
    print("=== KERNELS Permit Integration Example ===\n")

    # Step 1: Boot kernel with configuration
    print("1. Booting StrictKernel...")
    clock = VirtualClock(initial_ms=1000)
    config = KernelConfig(
        kernel_id="example-kernel",
        variant="strict",
        clock=clock,
        # Must match the permit's jurisdiction. The historical default is
        # "default"; this example uses a named jurisdiction.
        jurisdiction="production",
    )

    kernel = StrictKernel()
    kernel.boot(config)
    print(f"   Kernel state: {kernel.get_state()}")

    # Step 2: Set up HMAC keyring for permit verification
    print("\n2. Configuring permit verification...")
    HMAC_KEY = b"example-secret-key-32bytes-long!!"
    keyring = {"production-key-v1": HMAC_KEY}
    kernel.set_keyring(keyring)
    print("   Keyring configured with 1 key")

    # Step 3: Create a permit token (normally done by cockpit/operator)
    print("\n3. Creating permit token...")
    builder = PermitBuilder()
    permit = (
        builder.issuer("operator@example.com")
        .subject("ai-agent-001")
        .jurisdiction("production")
        .action("echo")  # Authorize 'echo' tool
        .params({"text": "Hello KERNELS"})
        .constraints(
            {
                "max_time_ms": 5000,
                "forbidden_params": [],
            }
        )
        .max_executions(1)  # Single-use permit
        .valid_from_ms(0)
        .valid_until_ms(clock.now_ms() + 3600_000)  # Valid for 1 hour
        .evidence_hash("evidence-packet-hash-abc123")
        .proposal_hash("proposal-hash-def456")
        .build(keyring, "production-key-v1")
    )
    print(f"   Permit ID: {permit.permit_id[:16]}...")
    print(f"   Issuer: {permit.issuer}")
    print(f"   Subject: {permit.subject}")
    print(f"   Action: {permit.action}")
    print(f"   Max executions: {permit.max_executions}")

    # Step 4: Submit request with permit
    print("\n4. Submitting request with permit...")
    request = KernelRequest(
        request_id="req-001",
        ts_ms=clock.now_ms(),
        actor="ai-agent-001",
        intent="Echo a greeting message",
        tool_call=ToolCall(name="echo", params={"text": "Hello KERNELS"}),
        params={"text": "Hello KERNELS"},
    )

    receipt = kernel.submit(request, permit_token=permit)

    print(f"   Receipt status: {receipt.status}")
    print(f"   Decision: {receipt.decision}")
    print(f"   Tool result: {receipt.tool_result}")

    # Step 5: Extract audit evidence
    print("\n5. Extracting audit evidence...")
    evidence = kernel.export_evidence()
    print(f"   Kernel ID: {evidence.kernel_id}")
    print(f"   Variant: {evidence.variant}")
    print(f"   Ledger entries: {len(evidence.ledger_entries)}")

    # Step 6: Examine audit entry
    print("\n6. Audit entry details:")
    entry = evidence.ledger_entries[0]
    print(f"   Request ID: {entry.request_id}")
    print(f"   Actor: {entry.actor}")
    print(f"   Decision: {entry.decision}")
    print(f"   Tool name: {entry.tool_name}")
    print(f"   Permit verified: {entry.permit_verification}")
    print(
        f"   Permit digest: {entry.permit_digest[:16]}..."
        if entry.permit_digest
        else "   Permit digest: None"
    )
    print(f"   Proposal hash: {entry.proposal_hash}")
    print(f"   Denial reasons: {entry.permit_denial_reasons}")

    # Step 7: Demonstrate replay protection
    print("\n7. Testing replay protection...")
    clock.advance(1000)
    request2 = KernelRequest(
        request_id="req-002",
        ts_ms=clock.now_ms(),
        actor="ai-agent-001",
        intent="Try to replay permit",
        tool_call=ToolCall(name="echo", params={"text": "Hello KERNELS"}),
        params={"text": "Hello KERNELS"},
    )

    receipt2 = kernel.submit(request2, permit_token=permit)  # Same permit!
    print(f"   Replay attempt status: {receipt2.status}")
    print(f"   Replay attempt decision: {receipt2.decision}")
    print(f"   Error: {receipt2.error}")

    evidence2 = kernel.export_evidence()
    # A successful call writes an intent record and an outcome record.
    # The replay denial is the last entry, not the second one.
    entry2 = evidence2.ledger_entries[-1]
    print(f"   Replay denial reasons: {entry2.permit_denial_reasons}")

    print("\n=== Example complete ===")
    print("\nKey takeaways:")
    print("- Permits enforce authorization at kernel level")
    print("- Every permit verification is audited")
    print("- Replay protection prevents permit reuse")
    print("- Full evidence chain: request → permit → proposal → evidence")


if __name__ == "__main__":
    main()
