"""Boundary tests for SDK fluent builders."""

import pytest

from kernels.sdk.builder import (
    PolicyBuilder,
    RequestBuilder,
    ToolCallBuilder,
    policy,
    request,
    tool_call,
)


def test_request_builder_requires_actor_and_intent():
    with pytest.raises(ValueError, match="actor is required"):
        RequestBuilder().build()
    with pytest.raises(ValueError, match="intent is required"):
        RequestBuilder().with_actor("agent").build()


def test_request_builder_builds_constraints_evidence_and_default_id():
    built = (
        request()
        .with_actor("agent")
        .with_intent("execute")
        .with_param("key", "value")
        .with_constraints(scope="repo", non_goals=["delete"], success_criteria=["test"])
        .with_evidence("ticket-1", "ticket-2")
        .with_metadata("source", "test")
        .build()
    )
    assert built.request_id.startswith("req-")
    assert built.tool_call is None
    assert built.params["key"] == "value"
    assert built.params["constraints"]["scope"] == "repo"
    assert built.evidence == "ticket-1\nticket-2"


def test_request_builder_tool_and_reset():
    builder = RequestBuilder().with_id("fixed").with_actor("agent").with_intent("run")
    builder.with_tool("echo").with_param("message", "hi")
    built = builder.build()
    assert built.request_id == "fixed"
    assert built.tool_call.name == "echo"
    assert built.tool_call.params["message"] == "hi"
    builder.reset()
    with pytest.raises(ValueError, match="actor is required"):
        builder.build()


def test_policy_builder_modes_and_reset():
    strict = PolicyBuilder.strict().allow_actor("operator").allow_tool("echo").build()
    assert strict.allowed_actors == frozenset({"operator"})
    assert strict.allowed_tools == frozenset({"echo"})
    assert strict.allow_intent_only is False

    permissive = PolicyBuilder.permissive().build()
    assert permissive.allow_intent_only is True
    assert permissive.max_intent_length == 10000

    builder = policy().allow_actors("a", "b").allow_tools("read", "write")
    builder.require_tool_call(False).with_max_intent_length(20)
    assert builder.build().allow_intent_only is True
    assert builder.reset().build().allowed_actors == frozenset()


def test_tool_call_builder_and_helpers():
    call = tool_call("echo").with_param("one", 1).with_params({"two": 2}).build()
    assert call.name == "echo"
    assert call.params == {"one": 1, "two": 2}
    assert ToolCallBuilder("noop").build().params == {}
