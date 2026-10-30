"""Tests for runtime choke-point behavior."""

import unittest

from shards_kernel.common.types import KernelConfig, KernelRequest, ReceiptStatus, ToolCall, VirtualClock
from shards_kernel.core.runtime import (
    ArtifactRef,
    ExecutionContext,
    KernelRuntime,
    TaskGraph,
    TaskNode,
)
from shards_kernel.execution.dispatcher import Dispatcher
from shards_kernel.execution.tools import create_default_registry
from shards_kernel.memory.artifact_store import ArtifactStore
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel


class TestKernelRuntimeHooks(unittest.TestCase):
    """Ensure all execution flows through KernelRuntime hooks."""

    def setUp(self) -> None:
        self.clock = VirtualClock(initial_ms=1000)
        self.config = KernelConfig(kernel_id="runtime-test", variant="strict", clock=self.clock)
        self.kernel = StrictKernel()
        self.kernel.boot(self.config)

        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}
        self.kernel.set_keyring(self.keyring)

    def _permit(self, *, constraints: dict[str, object], max_executions: int = 1):
        return (
            PermitBuilder()
            .issuer("operator1")
            .subject("agent1")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "hello"})
            .constraints(constraints)
            .max_executions(max_executions)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("evidence")
            .proposal_hash("proposal")
            .build(self.keyring, "key1")
        )

    def test_runtime_hooks_receive_execution_context(self) -> None:
        calls: list[tuple[str, str]] = []

        def before(context, tool_call):
            calls.append(("before", f"{context.trace_id}:{tool_call.name}"))

        def after(context, tool_call, result):
            tag = "ok" if result.dispatcher_result.success else "fail"
            calls.append(("after", f"{context.trace_id}:{tool_call.name}:{tag}"))

        self.kernel.set_runtime_hooks(before_execute=before, after_execute=after)

        request = KernelRequest(
            request_id="req-runtime-1",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        receipt = self.kernel.submit(request, permit_token=self._permit(constraints={}))

        self.assertEqual(receipt.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(
            calls,
            [
                ("before", "req-runtime-1:echo"),
                ("after", "req-runtime-1:echo:ok"),
            ],
        )

    def test_runtime_budget_violation_fails_execution(self) -> None:
        request = KernelRequest(
            request_id="req-runtime-2",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        permit = self._permit(constraints={"max_time_ms": -1})
        receipt = self.kernel.submit(request, permit_token=permit)

        self.assertEqual(receipt.status, ReceiptStatus.FAILED)
        self.assertIsNotNone(receipt.error)
        self.assertIn("Execution budget exceeded", receipt.error)

    def test_before_hook_can_deny_execution(self) -> None:
        request = KernelRequest(
            request_id="req-runtime-3",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        def before(_context, _tool_call):
            return "blocked-by-policy"

        self.kernel.set_runtime_hooks(before_execute=before)
        receipt = self.kernel.submit(request, permit_token=self._permit(constraints={}))

        self.assertEqual(receipt.status, ReceiptStatus.FAILED)
        self.assertIsNotNone(receipt.error)
        self.assertIn("Execution denied by hook", receipt.error)

    def test_runtime_emits_events_and_deduplicates(self) -> None:
        events: list[str] = []

        def sink(event):
            events.append(event.event_type)

        self.kernel.set_runtime_hooks(event_sink=sink)
        permit = self._permit(constraints={}, max_executions=2)
        request = KernelRequest(
            request_id="req-runtime-4",
            ts_ms=1000,
            actor="agent1",
            intent="Echo hello",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
            params={"text": "hello"},
        )

        receipt_1 = self.kernel.submit(request, permit_token=permit)
        receipt_2 = self.kernel.submit(request, permit_token=permit)

        self.assertEqual(receipt_1.status, ReceiptStatus.ACCEPTED)
        self.assertEqual(receipt_2.status, ReceiptStatus.ACCEPTED)
        self.assertIn("task.started", events)
        self.assertIn("tool.called", events)
        self.assertIn("tool.completed", events)
        self.assertIn("tool.deduplicated", events)


class TestKernelRuntimeGraphExecution(unittest.TestCase):
    """Validate deterministic graph execution semantics."""

    def setUp(self) -> None:
        self.runtime = KernelRuntime(
            Dispatcher(create_default_registry()),
            now_ms=lambda: 1000,
        )
        self.context = ExecutionContext(
            trace_id="trace-graph-1",
            actor="agent1",
            state_ref="EXECUTING",
            policy_ref="jurisdiction:active",
            idempotency_key="trace-graph-1",
            max_calls=10,
        )

    def test_execute_graph_orders_nodes_deterministically(self) -> None:
        graph = TaskGraph(
            graph_id="graph-1",
            nodes=(
                TaskNode(
                    node_id="b",
                    tool_call=ToolCall(name="echo", params={"text": "b"}),
                    depends_on=("a",),
                ),
                TaskNode(
                    node_id="a",
                    tool_call=ToolCall(name="echo", params={"text": "a"}),
                ),
                TaskNode(
                    node_id="c",
                    tool_call=ToolCall(name="echo", params={"text": "c"}),
                    depends_on=("b",),
                    input_artifacts=(
                        ArtifactRef(
                            artifact_id="node:b",
                            required_type="tool.result",
                        ),
                    ),
                ),
            ),
        )

        result = self.runtime.execute_graph(graph, self.context)

        self.assertTrue(result.success)
        self.assertEqual(result.execution_order, ("a", "b", "c"))
        self.assertEqual(
            result.node_results["a"].dispatcher_result.result,
            "a",
        )
        self.assertEqual(
            result.node_results["b"].dispatcher_result.result,
            "b",
        )
        self.assertEqual(
            result.node_results["c"].dispatcher_result.result,
            "c",
        )
        self.assertEqual(len(result.output_artifacts), 3)

    def test_execute_graph_detects_cycles(self) -> None:
        graph = TaskGraph(
            graph_id="graph-cycle",
            nodes=(
                TaskNode(
                    node_id="a",
                    tool_call=ToolCall(name="echo", params={"text": "a"}),
                    depends_on=("b",),
                ),
                TaskNode(
                    node_id="b",
                    tool_call=ToolCall(name="echo", params={"text": "b"}),
                    depends_on=("a",),
                ),
            ),
        )

        with self.assertRaises(ValueError):
            self.runtime.execute_graph(graph, self.context)

    def test_execute_graph_fails_on_missing_input_artifact(self) -> None:
        graph = TaskGraph(
            graph_id="graph-missing-artifact",
            nodes=(
                TaskNode(
                    node_id="a",
                    tool_call=ToolCall(name="echo", params={"text": "a"}),
                    input_artifacts=(
                        ArtifactRef(artifact_id="missing", required_type="tool.result"),
                    ),
                ),
            ),
        )

        result = self.runtime.execute_graph(graph, self.context)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
        self.assertIn("Missing input artifact", result.error)

    def test_execute_graph_fails_on_schema_mismatch(self) -> None:
        graph = TaskGraph(
            graph_id="graph-schema-mismatch",
            nodes=(
                TaskNode(
                    node_id="a",
                    tool_call=ToolCall(name="echo", params={"text": "a"}),
                ),
                TaskNode(
                    node_id="b",
                    tool_call=ToolCall(name="echo", params={"text": "b"}),
                    input_artifacts=(
                        ArtifactRef(
                            artifact_id="node:a",
                            required_type="tool.result",
                            required_schema_version="v2",
                        ),
                    ),
                ),
            ),
        )

        result = self.runtime.execute_graph(graph, self.context)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
        self.assertIn("schema mismatch", result.error)

    def test_execute_graph_fails_when_budget_exhausted(self) -> None:
        budgeted_context = ExecutionContext(
            trace_id="trace-budget",
            actor="agent1",
            state_ref="EXECUTING",
            policy_ref="jurisdiction:active",
            max_calls=1,
        )
        graph = TaskGraph(
            graph_id="graph-budget",
            nodes=(
                TaskNode(
                    node_id="a",
                    tool_call=ToolCall(name="echo", params={"text": "a"}),
                ),
                TaskNode(
                    node_id="b",
                    tool_call=ToolCall(name="echo", params={"text": "b"}),
                    depends_on=("a",),
                ),
            ),
        )

        result = self.runtime.execute_graph(graph, budgeted_context)
        self.assertFalse(result.success)
        self.assertEqual(result.execution_order, ("a",))
        self.assertEqual(result.error, "Graph call budget exhausted")


class TestArtifactStoreInvariants(unittest.TestCase):
    """Validate immutability and content-addressing invariants."""

    def test_artifact_store_rejects_non_content_address_id(self) -> None:
        store = ArtifactStore()
        with self.assertRaises(ValueError):
            store.put(
                artifact_id="manual-id",
                artifact_type="tool.result",
                schema_version="v1",
                value={"x": 1},
                provenance=("g1", "n1"),
            )


if __name__ == "__main__":
    unittest.main()
