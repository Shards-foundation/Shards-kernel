"""Failure-path and invariant tests for the canonical runtime boundary."""

from unittest.mock import patch

import pytest

from kernels.common.types import ToolCall
from kernels.core.runtime import (
    ArtifactRef,
    ExecutionContext,
    KernelRuntime,
    RuntimeEvent,
    RuntimeState,
    TaskGraph,
    TaskNode,
)
from kernels.execution.dispatcher import Dispatcher
from kernels.execution.tools import create_default_registry


def context(**overrides):
    values = dict(
        trace_id="trace-edge",
        actor="agent",
        state_ref="EXECUTING",
        policy_ref="policy:test",
    )
    values.update(overrides)
    return ExecutionContext(**values)


def runtime(**kwargs):
    return KernelRuntime(Dispatcher(create_default_registry()), now_ms=lambda: 123, **kwargs)


def test_runtime_state_reducer_ignores_unrelated_and_missing_identifiers():
    events = [
        RuntimeEvent("1", "node.completed", None, "t", None, "node-a", None, 1, {}),
        RuntimeEvent("2", "node.failed", None, "t", None, "node-b", None, 2, {}),
        RuntimeEvent("3", "node.completed", None, "t", None, None, None, 3, {}),
        RuntimeEvent("4", "artifact.created", None, "t", None, None, None, 4, {"artifact_id": "a1"}),
        RuntimeEvent("5", "artifact.created", None, "t", None, None, None, 5, {"artifact_id": ""}),
        RuntimeEvent("6", "other.event", None, "t", None, "ignored", None, 6, {}),
    ]
    state = RuntimeState.reduce_events(events)
    assert state.completed_nodes == frozenset({"node-a"})
    assert state.failed_nodes == frozenset({"node-b"})
    assert state.created_artifacts == frozenset({"a1"})


def test_call_budget_denial_emits_error_without_dispatching():
    events = []
    result = runtime(event_sink=events.append).execute(
        ToolCall("echo", {"text": "must-not-run"}),
        context(max_calls=0),
    )
    assert result.dispatcher_result.success is False
    assert result.budget_exceeded is True
    assert "Call budget exceeded" in result.dispatcher_result.error
    assert [event.event_type for event in events] == ["task.started", "error.raised"]


def test_execution_failure_invokes_error_and_after_hooks():
    errors = []
    after = []
    events = []
    rt = runtime(
        on_error=lambda ctx, call, result: errors.append((ctx.trace_id, call.name, result)),
        after_execute=lambda ctx, call, result: after.append((call.name, result.dispatcher_result.success)),
        event_sink=events.append,
    )
    result = rt.execute(ToolCall("tool-does-not-exist", {}), context())
    assert result.dispatcher_result.success is False
    assert errors and errors[0][:2] == ("trace-edge", "tool-does-not-exist")
    assert after == [("tool-does-not-exist", False)]
    assert "error.raised" in [event.event_type for event in events]


def test_before_hook_denial_calls_error_hook_but_not_after_hook():
    errors = []
    after = []
    events = []
    rt = runtime(
        before_execute=lambda _ctx, _call: "risk policy",
        on_error=lambda _ctx, _call, result: errors.append(result),
        after_execute=lambda *_args: after.append(True),
        event_sink=events.append,
    )
    result = rt.execute(ToolCall("echo", {"text": "blocked"}), context())
    assert result.denied_by_hook is True
    assert "risk policy" in result.dispatcher_result.error
    assert len(errors) == 1
    assert after == []
    assert "policy.denied" in [event.event_type for event in events]


def test_execution_time_budget_converts_success_to_failure():
    rt = runtime()
    with patch("kernels.core.runtime.perf_counter", side_effect=[1.0, 1.1]):
        result = rt.execute(
            ToolCall("echo", {"text": "hello"}),
            context(max_time_ms=1, idempotency_key="time-budget-test"),
        )
    assert result.budget_exceeded is True
    assert result.dispatcher_result.success is False
    assert "Execution budget exceeded" in result.dispatcher_result.error


def test_graph_order_rejects_duplicate_nodes_and_unknown_dependencies():
    rt = runtime()
    duplicate = TaskGraph(
        "duplicates",
        (
            TaskNode("same", ToolCall("echo", {"text": "a"})),
            TaskNode("same", ToolCall("echo", {"text": "b"})),
        ),
    )
    with pytest.raises(ValueError, match="duplicate node IDs"):
        rt._resolve_execution_order(duplicate)

    unknown = TaskGraph(
        "unknown-dependency",
        (TaskNode("a", ToolCall("echo", {"text": "a"}), depends_on=("missing",)),),
    )
    with pytest.raises(ValueError, match="unknown node"):
        rt._resolve_execution_order(unknown)


def test_graph_rejects_existing_artifact_with_wrong_type():
    rt = runtime()
    graph = TaskGraph(
        "wrong-artifact-type",
        (
            TaskNode(
                "producer",
                ToolCall("echo", {"text": "payload"}),
                output_artifact_type="custom.payload",
            ),
            TaskNode(
                "consumer",
                ToolCall("echo", {"text": "consume"}),
                depends_on=("producer",),
                input_artifacts=(ArtifactRef("node:producer", required_type="tool.result"),),
            ),
        ),
    )
    result = rt.execute_graph(graph, context(max_calls=10))
    assert result.success is False
    assert "Artifact type mismatch" in result.error
    assert "consumer" not in result.node_results


def test_graph_records_failed_node_and_returns_partial_results():
    rt = runtime()
    graph = TaskGraph(
        "failed-node",
        (
            TaskNode("ok", ToolCall("echo", {"text": "first"})),
            TaskNode(
                "fails",
                ToolCall("missing-tool", {}),
                depends_on=("ok",),
            ),
        ),
    )
    result = rt.execute_graph(graph, context(max_calls=10))
    assert result.success is False
    assert result.execution_order == ("ok", "fails")
    assert "fails" in result.node_results
    assert result.error
