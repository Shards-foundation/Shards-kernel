"""SDK builders produce objects the kernel accepts."""

from shards_kernel import (
    Decision,
    KernelConfig,
    PermitBuilder,
    StrictKernel,
    VirtualClock,
)
from shards_kernel.sdk.builder import PolicyBuilder, RequestBuilder


KEYRING = {"k": b"test-secret-key-32-bytes-long123"}


def test_request_and_policy_builders_round_trip() -> None:
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="builders", variant="strict", clock=VirtualClock(0))
    )
    kernel.set_keyring(KEYRING)
    policy = (
        PolicyBuilder()
        .allow_actors("agent")
        .allow_tools("echo")
        .with_max_intent_length(500)
        .build()
    )
    kernel.set_policy(policy)

    request = (
        RequestBuilder()
        .with_id("req-1")
        .with_actor("agent")
        .with_intent("Echo hello")
        .with_tool("echo", {"text": "hello"})
        .with_evidence("ticket-1")
        .build()
    )
    assert request.params == {"text": "hello"}
    assert request.tool_call is not None
    assert request.tool_call.params == request.params
    assert request.evidence == "ticket-1"

    permit = (
        PermitBuilder()
        .issuer("operator")
        .subject("agent")
        .jurisdiction("default")
        .action("echo")
        .params(dict(request.params))
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .proposal_hash("proposal-echo")
        .build(KEYRING, "k")
    )
    receipt = kernel.submit(request, permit_token=permit)
    assert receipt.decision == Decision.ALLOW
    assert receipt.tool_result == "hello"


def test_custom_policy_rules_are_rejected() -> None:
    try:
        PolicyBuilder().with_custom_rule(lambda _request: None).build()
    except ValueError as exc:
        assert "custom_rules" in str(exc)
    else:
        raise AssertionError("custom rules must not build a policy")
