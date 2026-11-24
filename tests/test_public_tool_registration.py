"""The supported public tool-registration extension point."""

from __future__ import annotations

import pytest

from shards_kernel.common.errors import StateError, ToolError
from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)
from shards_kernel.execution.scope import current_execution_scope
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel

KEY = b"public-registration-test-key-32-bytes"


def _kernel(*, policy: JurisdictionPolicy) -> StrictKernel:
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="registration-kernel", variant="strict", clock=VirtualClock(1000))
    )
    kernel.set_policy(policy)
    kernel.set_keyring({"key1": KEY})
    return kernel


def _permit(action: str, params: dict, *, actor: str = "agent") -> object:
    return (
        PermitBuilder()
        .issuer("operator")
        .subject(actor)
        .jurisdiction("default")
        .action(action)
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("evidence")
        .proposal_hash("proposal")
        .build({"key1": KEY}, "key1")
    )


def test_register_and_execute_a_trusted_tool_with_a_signed_permit():
    seen: list[dict] = []
    scopes: list[object] = []

    def probe(value: int) -> dict:
        scopes.append(current_execution_scope())
        seen.append({"value": value})
        return {"value": value}

    kernel = _kernel(
        policy=JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"})
        )
    )
    kernel.register_tool("probe", probe, "test probe", {"value": int})
    permit = _permit("probe", {"value": 3})
    receipt = kernel.submit(
        KernelRequest(
            request_id="req-1",
            ts_ms=1000,
            actor="agent",
            intent="run probe",
            tool_call=ToolCall(name="probe", params={"value": 3}),
            params={"value": 3},
        ),
        permit_token=permit,
    )
    assert receipt.status is ReceiptStatus.ACCEPTED
    assert receipt.decision is Decision.ALLOW
    assert receipt.tool_result == {"value": 3}
    assert seen == [{"value": 3}]
    assert scopes[0] is not None
    assert scopes[0].request_id == "req-1"
    assert scopes[0].tool_name == "probe"
    assert scopes[0].permit_id == permit.permit_id
    assert current_execution_scope() is None


def test_registration_requires_an_explicit_non_wildcard_policy():
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="registration-kernel", variant="strict", clock=VirtualClock(1000))
    )
    # Boot installs the permissive default policy; registration must refuse it.
    with pytest.raises(ValueError, match="Explicit actor and tool allowlists"):
        kernel.register_tool("probe", lambda: None)
    kernel.set_policy(
        JurisdictionPolicy(allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"echo"}))
    )
    with pytest.raises(ValueError, match="explicit policy allowlist"):
        kernel.register_tool("probe", lambda: None)


def test_duplicate_and_replace_registration_are_explicit():
    kernel = _kernel(
        policy=JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"})
        )
    )
    kernel.register_tool("probe", lambda: "first")
    with pytest.raises(ToolError, match="already registered"):
        kernel.register_tool("probe", lambda: "second")
    kernel.register_tool("probe", lambda: "second", replace=True)
    receipt = kernel.submit(
        KernelRequest(
            request_id="req-1",
            ts_ms=1000,
            actor="agent",
            intent="run probe",
            tool_call=ToolCall(name="probe", params={}),
            params={},
        ),
        permit_token=_permit("probe", {}),
    )
    assert receipt.tool_result == "second"


@pytest.mark.parametrize(
    "name,handler",
    [
        ("", lambda: None),
        ("*", lambda: None),
        ("has space", lambda: None),
        ("probe", None),
    ],
)
def test_invalid_registration_inputs_are_refused(name, handler):
    kernel = _kernel(
        policy=JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"})
        )
    )
    with pytest.raises(ValueError):
        kernel.register_tool(name, handler)


def test_registration_requires_a_booted_kernel():
    with pytest.raises(StateError, match="Kernel not booted"):
        StrictKernel().register_tool("probe", lambda: None)


def test_registration_rejects_invalid_schema_and_signatures():
    kernel = _kernel(
        policy=JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"})
        )
    )
    with pytest.raises(ValueError, match="param_schema must be a dictionary"):
        kernel.register_tool("probe", lambda value: value, param_schema=[("value", int)])
    with pytest.raises(ValueError, match="param_schema values must be types"):
        kernel.register_tool("probe", lambda value: value, param_schema={"value": "int"})
    with pytest.raises(ValueError, match="must match the handler parameters"):
        kernel.register_tool("probe", lambda value: value, param_schema={"other": int})

    def variadic(*values):
        return values

    with pytest.raises(ValueError, match="variadic"):
        kernel.register_tool("probe", variadic, param_schema={})

    def annotated(value: int) -> dict:
        return {"value": value}

    with pytest.raises(ValueError, match="does not match handler annotation"):
        kernel.register_tool("probe", annotated, param_schema={"value": str})

    def unresolved(value: "MissingType"):  # noqa: F821
        return value

    kernel.register_tool("probe", unresolved, param_schema={"value": object})


class _Uninspectable:
    def __call__(self):
        return None

    @property
    def __signature__(self):
        raise TypeError("not inspectable")


def test_registration_rejects_uninspectable_handler():
    kernel = _kernel(
        policy=JurisdictionPolicy(
            allowed_actors=frozenset({"agent"}), allowed_tools=frozenset({"probe"})
        )
    )
    with pytest.raises(ValueError, match="not inspectable"):
        kernel.register_tool("probe", _Uninspectable(), param_schema={})


def test_builtin_echo_and_add_remain_available_and_unchanged():
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="registration-kernel", variant="strict", clock=VirtualClock(1000))
    )
    assert {"echo", "add"}.issubset(set(kernel._dispatcher.registry.list_tools()))
    assert kernel._dispatcher.registry.get("echo").handler("hello") == "hello"
    assert kernel._dispatcher.registry.get("add").handler(2, 3) == 5
