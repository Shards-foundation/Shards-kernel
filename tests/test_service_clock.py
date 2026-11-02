"""Real-time permit expiry and fail-closed service clock regression tests."""

import pytest

from shards_kernel.common.time import ClockRollbackError, SystemClock
from shards_kernel.common.types import Decision, KernelConfig, KernelRequest, ToolCall, VirtualClock
from shards_kernel.integrations.mcp_adapter import create_mcp_adapter
from shards_kernel.integrations.wire import boot_service_kernel, boot_strict_kernel
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel


KEYRING = {"operator": b"service-clock-test-key-32-bytes-long"}


def test_service_boot_uses_real_time_and_deny_all_policy():
    service = boot_service_kernel("clock-service")
    assert isinstance(service.config.clock, SystemClock)
    assert service.config.clock.now_ms() > 1_700_000_000_000
    assert service.policy.allowed_actors == frozenset()
    assert service.policy.allowed_tools == frozenset()

    test_kernel = boot_strict_kernel("deterministic-tests")
    assert isinstance(test_kernel.config.clock, VirtualClock)
    assert test_kernel.config.clock.now_ms() == 0

    adapter = create_mcp_adapter(kernel_id="mcp-service-clock")
    assert isinstance(adapter.kernel.config.clock, SystemClock)
    assert adapter.kernel.policy.allowed_actors == frozenset()


def test_system_clock_detects_backward_time_and_remains_unsafe():
    samples = iter([1_000_000_000, 1_001_000_000, 999_000_000, 2_000_000_000])
    clock = SystemClock(source_ns=lambda: next(samples))
    assert clock.now_ms() == 1000
    assert clock.now_ms() == 1001
    with pytest.raises(ClockRollbackError, match="backwards"):
        clock.now_ms()
    with pytest.raises(ClockRollbackError, match="previously"):
        clock.now_ms()


@pytest.mark.parametrize("sample", [-1, "bad", True])
def test_system_clock_rejects_invalid_samples(sample):
    clock = SystemClock(source_ns=lambda: sample)
    with pytest.raises(ClockRollbackError, match="invalid"):
        clock.now_ms()
    with pytest.raises(ClockRollbackError, match="previously"):
        clock.now_ms()


def test_system_clock_source_failure_is_sticky():
    def failed():
        raise OSError("system clock unavailable")

    clock = SystemClock(source_ns=failed)
    with pytest.raises(ClockRollbackError, match="unavailable"):
        clock.now_ms()
    with pytest.raises(ClockRollbackError, match="previously"):
        clock.now_ms()


def test_permit_expiration_rejects_side_effect_under_wall_clock():
    wall = {"now_ms": 1_800_000_000_000}
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id="wall-expiry",
            variant="strict",
            clock=SystemClock(source_ns=lambda: wall["now_ms"] * 1_000_000),
        )
    )
    kernel.set_keyring(KEYRING)
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"agent-1"}),
            allowed_tools=frozenset({"echo"}),
        )
    )
    params = {"text": "never execute"}
    permit = (
        PermitBuilder()
        .issuer("operator")
        .subject("agent-1")
        .jurisdiction("default")
        .action("echo")
        .params(params)
        .max_executions(1)
        .valid_from_ms(wall["now_ms"] - 1_000)
        .valid_until_ms(wall["now_ms"] + 1_000)
        .proposal_hash("expiry-proposal")
        .build(KEYRING, "operator")
    )
    request = KernelRequest(
        request_id="expiry-1",
        ts_ms=wall["now_ms"],
        actor="agent-1",
        intent="Echo only if permit has not expired",
        tool_call=ToolCall(name="echo", params=dict(params)),
        params=dict(params),
    )

    # Simulate real time advancing beyond the signed expiry before submission.
    wall["now_ms"] += 1_001
    receipt = kernel.submit(request, permit_token=permit)
    assert receipt.decision == Decision.DENY
    assert receipt.tool_result is None
    assert kernel.export_evidence().ledger_entries[-1].decision == Decision.DENY


def test_default_http_framework_factories_do_not_use_virtual_time():
    flask = pytest.importorskip("flask")
    from shards_kernel.integrations.flask_adapter import create_flask_app

    app = create_flask_app(
        kernel_id="flask-time",
        api_key="service-clock-test-http-api-key-32-characters",
    )
    assert isinstance(app.config["kernel"].config.clock, SystemClock)

    pytest.importorskip("fastapi")
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app

    api = create_fastapi_app(
        kernel_id="fastapi-time",
        api_key="service-clock-test-http-api-key-32-characters",
    )
    assert isinstance(api.state.kernel.config.clock, SystemClock)
