"""Boundary tests for deterministic codecs and request validation."""

import pytest

from kernels.common.codec import deserialize, serialize_deterministic, serialize_for_audit
from kernels.common.types import KernelRequest, ToolCall
from kernels.common.validate import check_ambiguity, check_param_size, validate_tool_call


def req(**changes):
    values = dict(request_id="r", ts_ms=0, actor="operator", intent="ok", params={})
    values.update(changes)
    return KernelRequest(**values)


@pytest.mark.parametrize(
    "call, expected",
    [
        ({"params": {}}, "tool_call.name is required"),
        ({"name": 2}, "tool_call.name must be a string"),
        ({"name": ""}, "tool_call.name cannot be empty"),
        ({"name": "echo", "params": []}, "tool_call.params must be a dictionary"),
        (object(), "tool_call has invalid structure"),
        (ToolCall(name=""), "tool_call.name is required"),
    ],
)
def test_tool_call_rejects_invalid_shapes(call, expected):
    assert expected in validate_tool_call(call)


def test_tool_call_accepts_valid_shapes():
    assert validate_tool_call({"name": "echo", "params": {"x": 1}}) == []
    assert validate_tool_call(ToolCall("echo", {"x": 1})) == []


def test_ambiguity_checks_empty_long_and_invalid_tool_calls():
    assert check_ambiguity(req(intent="  "))
    assert check_ambiguity(req(intent="long"), max_intent_length=3)
    assert check_ambiguity(req(tool_call={"name": ""}), strict=True)
    assert check_ambiguity(req(tool_call=object()), strict=True)
    assert check_ambiguity(req(params=[]))
    assert check_ambiguity(req(tool_call={"name": ""}), strict=False) == []


def test_param_size_uses_utf8_serialized_size():
    assert not check_param_size({}, max_bytes=0)
    assert check_param_size({"x": "é"}, max_bytes=10)
    assert not check_param_size({"x": "é"}, max_bytes=7)


def test_param_size_propagates_serialization_errors():
    with pytest.raises(TypeError):
        check_param_size({"x": object()})


def test_deterministic_json_sorts_keys_and_round_trips():
    value = {"z": 1, "a": {"y": 2, "b": 3}}
    encoded = serialize_deterministic(value)
    assert encoded == '{"a":{"b":3,"y":2},"z":1}'
    assert deserialize(encoded) == value


def test_deterministic_json_rejects_unserializable_values():
    with pytest.raises(TypeError):
        serialize_deterministic({"x": object()})


def test_audit_serialization_handles_optional_denial_reasons():
    common = dict(
        request_id="r", actor="a", intent="i", decision="DENY",
        state_from="IDLE", state_to="HALTED", ts_ms=1,
    )
    empty = deserialize(serialize_for_audit(**common))
    denied = deserialize(
        serialize_for_audit(**common, permit_denial_reasons=("EXPIRED", "REPLAY"))
    )
    assert empty["permit_denial_reasons"] is None
    assert denied["permit_denial_reasons"] == ["EXPIRED", "REPLAY"]
