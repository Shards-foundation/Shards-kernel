#!/usr/bin/env python3
"""Example 02: Tool execution.

A tool runs only when request.params and the tool-call params are the same,
and a permit authorises that exact call. An unpermitted call is denied.
"""

from shards_kernel.common.types import KernelConfig, KernelRequest, ToolCall, VirtualClock
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel

KEYRING = {"example-key": b"example-secret-key-32bytes-long!"}


def permit_for(action: str, params: dict, valid_until_ms: int):
    """Build a single-use permit for one tool call."""
    return (
        PermitBuilder()
        .issuer("operator")
        .subject("tool-user")
        .jurisdiction("default")
        .action(action)
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(valid_until_ms)
        .evidence_hash("evidence")
        .proposal_hash("proposal")
        .build(KEYRING, "example-key")
    )


def main() -> None:
    """Run tool execution example."""
    kernel = StrictKernel()
    clock = VirtualClock(1000)
    kernel.boot(
        KernelConfig(
            kernel_id="tool-example-001",
            variant="strict",
            clock=clock,
        )
    )
    kernel.set_keyring(KEYRING)

    print("Kernel booted with built-in tools: echo, add")
    print("-" * 50)

    print("\n[Unpermitted echo]")
    denied = kernel.submit(
        KernelRequest(
            request_id="req-denied-001",
            ts_ms=1000,
            actor="tool-user",
            intent="Echo without a permit",
            tool_call=ToolCall(name="echo", params={"text": "should not run"}),
            params={"text": "should not run"},
        )
    )
    print(f"Decision: {denied.decision.value}")
    print(f"Error: {denied.error}")

    echo_params = {"text": "Hello from the kernel!"}
    echo_request = KernelRequest(
        request_id="req-echo-001",
        ts_ms=1000,
        actor="tool-user",
        intent="Echo a message through the kernel",
        tool_call=ToolCall(name="echo", params=dict(echo_params)),
        params=dict(echo_params),
    )
    print("\n[Echo tool]")
    receipt = kernel.submit(
        echo_request,
        permit_token=permit_for("echo", echo_params, clock.now_ms() + 10_000),
    )
    print(f"Status: {receipt.status.value}")
    print(f"Decision: {receipt.decision.value}")
    print(f"Result: {receipt.tool_result}")

    add_params = {"a": 17, "b": 25}
    add_request = KernelRequest(
        request_id="req-add-001",
        ts_ms=2000,
        actor="tool-user",
        intent="Add two numbers",
        tool_call=ToolCall(name="add", params=dict(add_params)),
        params=dict(add_params),
    )
    print("\n[Add tool]")
    receipt = kernel.submit(
        add_request,
        permit_token=permit_for("add", add_params, clock.now_ms() + 10_000),
    )
    print(f"Status: {receipt.status.value}")
    print(f"Decision: {receipt.decision.value}")
    print(f"Result: {receipt.tool_result}")

    unknown_params: dict = {}
    unknown_request = KernelRequest(
        request_id="req-unknown-001",
        ts_ms=3000,
        actor="tool-user",
        intent="Try to use an unknown tool",
        tool_call=ToolCall(name="unknown_tool", params=dict(unknown_params)),
        params=dict(unknown_params),
    )
    print("\n[Unknown tool]")
    receipt = kernel.submit(
        unknown_request,
        permit_token=permit_for("unknown_tool", unknown_params, clock.now_ms() + 10_000),
    )
    print(f"Status: {receipt.status.value}")
    print(f"Decision: {receipt.decision.value}")
    print(f"Error: {receipt.error}")

    evidence = kernel.export_evidence()
    print("\n" + "-" * 50)
    print(f"Total audit entries: {len(evidence.ledger_entries)}")
    print(f"Root hash: {evidence.root_hash[:32]}...")


if __name__ == "__main__":
    main()
