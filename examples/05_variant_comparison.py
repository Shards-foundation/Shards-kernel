#!/usr/bin/env python3
"""Example 05: Variant Comparison

Demonstrates behavioral differences between kernel variants using the same
request patterns.
"""

from shards_kernel.common.types import (
    KernelConfig,
    KernelRequest,
    ToolCall,
    VirtualClock,
)
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel
from _permit import issue_permit

KEYRING = {"example-key": b"example-secret-key-32bytes-long!"}


def make_config(kernel_id: str, variant: str) -> KernelConfig:
    """Create a test configuration."""
    return KernelConfig(
        kernel_id=kernel_id,
        variant=variant,
        clock=VirtualClock(1000),
    )


def test_variant(kernel, variant_name: str, requests: list, permit=None) -> None:
    """Test a kernel variant with a list of requests."""
    print(f"\n{'=' * 60}")
    print(f"VARIANT: {variant_name}")
    print("=" * 60)
    kernel.set_keyring(KEYRING)

    for name, request in requests:
        print(f"\n[{name}]")
        token = permit if request.request_id == "req-tool" else None
        receipt = kernel.submit(request, permit_token=token)
        print(f"  Decision: {receipt.decision.value}")
        print(f"  Status: {receipt.status.value}")
        if receipt.error:
            error_preview = (
                receipt.error[:60] + "..." if len(receipt.error) > 60 else receipt.error
            )
            print(f"  Error: {error_preview}")
        if receipt.tool_result is not None:
            print(f"  Result: {receipt.tool_result}")


def main() -> None:
    """Run variant comparison example."""
    print("Kernel Variant Comparison")
    print("Demonstrating behavioral differences across variants")

    # Define test requests
    intent_only_request = (
        "Intent-Only Request",
        KernelRequest(
            request_id="req-intent",
            ts_ms=1000,
            actor="test-user",
            intent="A request with intent but no tool call",
        ),
    )

    echo_params = {"text": "hello"}
    tool_permit = issue_permit(
        KEYRING,
        "example-key",
        subject="test-user",
        action="echo",
        params=echo_params,
        max_executions=4,
    )
    tool_request = (
        "Permitted tool request",
        KernelRequest(
            request_id="req-tool",
            ts_ms=2000,
            actor="test-user",
            intent="Execute echo tool",
            tool_call=ToolCall(name="echo", params=dict(echo_params)),
            params=dict(echo_params),
        ),
    )
    unpermitted_tool = (
        "Unpermitted tool request",
        KernelRequest(
            request_id="req-tool-denied",
            ts_ms=2500,
            actor="test-user",
            intent="Execute echo without a permit",
            tool_call=ToolCall(name="echo", params={"text": "nope"}),
            params={"text": "nope"},
        ),
    )

    evidence_request = (
        "Request with Evidence",
        KernelRequest(
            request_id="req-evidence",
            ts_ms=3000,
            actor="test-user",
            intent="Request with evidence attached",
            evidence="Supporting evidence for this request",
        ),
    )

    constraints_request = (
        "Request with Constraints",
        KernelRequest(
            request_id="req-constraints",
            ts_ms=4000,
            actor="test-user",
            intent="Request with dual-channel constraints",
            params={
                "constraints": {
                    "scope": "Limited to echo operations",
                    "non_goals": "No data modification",
                    "success_criteria": "Echo returns expected text",
                }
            },
        ),
    )

    # Test Strict Kernel
    strict = StrictKernel()
    strict.boot(make_config("strict-001", "strict"))
    test_variant(
        strict,
        "Strict Kernel",
        [
            intent_only_request,
            unpermitted_tool,
            tool_request,
        ],
        permit=tool_permit,
    )

    # Test Permissive Kernel
    permissive = PermissiveKernel()
    permissive.boot(make_config("permissive-001", "permissive"))
    test_variant(
        permissive,
        "Permissive Kernel",
        [
            intent_only_request,
            unpermitted_tool,
            tool_request,
        ],
        permit=tool_permit,
    )

    # Test Evidence-First Kernel
    evidence_first = EvidenceFirstKernel()
    evidence_first.boot(make_config("evidence-001", "evidence-first"))
    test_variant(
        evidence_first,
        "Evidence-First Kernel",
        [
            intent_only_request,  # Should fail (no evidence)
            evidence_request,  # Should pass (has evidence)
        ],
    )

    # Test Dual-Channel Kernel
    dual_channel = DualChannelKernel()
    dual_channel.boot(make_config("dual-001", "dual-channel"))
    test_variant(
        dual_channel,
        "Dual-Channel Kernel",
        [
            intent_only_request,  # Should fail (no constraints)
            constraints_request,  # Should pass (has constraints)
        ],
    )

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("""
Variant Behaviors:

  Strict Kernel:
    - Requires explicit tool_call for tool execution
    - Strict ambiguity detection
    - Fail-closed on any uncertainty

  Permissive Kernel:
    - Accepts intent-only requests
    - Relaxed ambiguity thresholds
    - Higher intent length limits

  Evidence-First Kernel:
    - Requires evidence field for all requests
    - Emphasizes audit trail completeness
    - Denies requests without evidence

  Dual-Channel Kernel:
    - Requires constraints dict in params
    - Constraints must include: scope, non_goals, success_criteria
    - Enables richer decision context
""")


if __name__ == "__main__":
    main()
