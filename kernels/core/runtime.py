"""Kernel runtime execution choke point.

All tool execution should pass through KernelRuntime.execute so policy, budget,
and observability hooks can be applied consistently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable, Optional

from kernels.common.hashing import compute_hash_dict
from kernels.common.types import ToolCall
from kernels.execution.dispatcher import Dispatcher, ExecutionResult
from kernels.memory.artifact_store import ArtifactStore
from kernels.memory.idempotency_store import IdempotencyRecord, IdempotencyStore


@dataclass(frozen=True)
class ExecutionContext:
    """Canonical execution context propagated across the runtime path."""

    trace_id: str
    actor: str
    state_ref: str
    policy_ref: str
    execution_identity: Optional[str] = None
    graph_id: Optional[str] = None
    node_id: Optional[str] = None
    strategy_snapshot: Optional[str] = None
    budget_ref: Optional[str] = None
    memory_ref: str = "memory:none"
    artifact_refs: tuple[str, ...] = field(default_factory=tuple)
    parent_event_id: Optional[str] = None
    causal_chain: tuple[str, ...] = field(default_factory=tuple)
    policy_snapshot: Optional[str] = None
    idempotency_key: Optional[str] = None
    max_time_ms: Optional[int] = None
    max_calls: Optional[int] = None
    call_index: int = 1
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeEvent:
    """Structured runtime event emitted during execution."""

    event_id: str
    event_type: str
    execution_identity: Optional[str]
    trace_id: str
    graph_id: Optional[str]
    node_id: Optional[str]
    parent_event_id: Optional[str]
    ts_ms: int
    payload: dict[str, str]


@dataclass(frozen=True)
class RuntimeExecutionResult:
    """Runtime result with context and optional budget violation markers."""

    dispatcher_result: ExecutionResult
    trace_id: str
    elapsed_ms: int
    budget_exceeded: bool
    denied_by_hook: bool = False
    deduplicated: bool = False


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to an artifact consumed by a node."""

    artifact_id: str
    required_type: Optional[str] = None
    required_schema_version: Optional[str] = None


@dataclass(frozen=True)
class Artifact:
    """Typed artifact produced by runtime execution."""

    artifact_id: str
    artifact_type: str
    schema_version: str
    value: object
    value_hash: str
    provenance: tuple[str, ...]
    created_event_id: Optional[str] = None
    parent_artifacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionIdentity:
    """Unified identity across runtime, events, and cache keys."""

    value: str
    node_id: Optional[str]
    graph_id: Optional[str]
    tool_name: str


@dataclass(frozen=True)
class TaskNode:
    """Single node in a deterministic execution graph."""

    node_id: str
    tool_call: ToolCall
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    input_artifacts: tuple[ArtifactRef, ...] = field(default_factory=tuple)
    output_artifact_type: str = "tool.result"
    output_schema_version: str = "v1"


@dataclass(frozen=True)
class TaskGraph:
    """Directed acyclic graph of runtime tasks."""

    graph_id: str
    nodes: tuple[TaskNode, ...]


@dataclass(frozen=True)
class GraphExecutionResult:
    """Execution result for a task graph."""

    trace_id: str
    node_results: dict[str, RuntimeExecutionResult]
    execution_order: tuple[str, ...]
    output_artifacts: dict[str, Artifact]
    success: bool
    error: Optional[str] = None


@dataclass(frozen=True)
class RuntimeState:
    """Reduced runtime state reconstructed from runtime events."""

    completed_nodes: frozenset[str] = frozenset()
    failed_nodes: frozenset[str] = frozenset()
    created_artifacts: frozenset[str] = frozenset()

    @staticmethod
    def reduce_events(events: list[RuntimeEvent]) -> "RuntimeState":
        """Reconstruct a minimal state projection from runtime events."""
        completed_nodes: set[str] = set()
        failed_nodes: set[str] = set()
        created_artifacts: set[str] = set()

        for event in events:
            node_id = event.node_id
            if event.event_type == "node.completed" and node_id is not None:
                completed_nodes.add(node_id)
            elif event.event_type == "node.failed" and node_id is not None:
                failed_nodes.add(node_id)
            elif event.event_type == "artifact.created":
                artifact_id = event.payload.get("artifact_id")
                if artifact_id:
                    created_artifacts.add(artifact_id)

        return RuntimeState(
            completed_nodes=frozenset(completed_nodes),
            failed_nodes=frozenset(failed_nodes),
            created_artifacts=frozenset(created_artifacts),
        )


@dataclass(frozen=True)
class GraphBudget:
    """Composable call budget for graph execution."""

    total_calls: int
    remaining_calls: int


class KernelRuntime:
    """Single kernel execution choke point.

    This class wraps dispatcher execution so every call can consistently apply:
    1) context propagation
    2) pre/post execution hooks
    3) execution-time budget checks
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        before_execute: Optional[
            Callable[[ExecutionContext, ToolCall], Optional[str]]
        ] = None,
        after_execute: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        on_error: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        event_sink: Optional[Callable[[RuntimeEvent], None]] = None,
        now_ms: Optional[Callable[[], int]] = None,
        artifact_store: Optional[ArtifactStore] = None,
        idempotency_store: Optional[IdempotencyStore] = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._before_execute = before_execute
        self._after_execute = after_execute
        self._on_error = on_error
        self._event_sink = event_sink
        self._now_ms = now_ms or (lambda: 0)
        self._result_cache: dict[str, RuntimeExecutionResult] = {}
        self._artifact_store = artifact_store or ArtifactStore()
        self._idempotency_store = idempotency_store or IdempotencyStore()

    @property
    def dispatcher(self) -> Dispatcher:
        """Expose dispatcher for explicit tool registration."""
        return self._dispatcher

    def set_hooks(
        self,
        *,
        before_execute: Optional[
            Callable[[ExecutionContext, ToolCall], Optional[str]]
        ] = None,
        after_execute: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        on_error: Optional[
            Callable[[ExecutionContext, ToolCall, RuntimeExecutionResult], None]
        ] = None,
        event_sink: Optional[Callable[[RuntimeEvent], None]] = None,
    ) -> None:
        """Replace runtime hooks used for observability or policy injection."""
        self._before_execute = before_execute
        self._after_execute = after_execute
        self._on_error = on_error
        self._event_sink = event_sink

    def _emit(
        self,
        event_type: str,
        context: ExecutionContext,
        payload: dict[str, str],
    ) -> RuntimeEvent:
        event = RuntimeEvent(
            event_id=compute_hash_dict(
                {
                    "trace_id": context.trace_id,
                    "event_type": event_type,
                    "parent_event_id": context.parent_event_id,
                    "call_index": context.call_index,
                    "payload": payload,
                    "ts_ms": self._now_ms(),
                }
            ),
            event_type=event_type,
            execution_identity=context.execution_identity,
            trace_id=context.trace_id,
            graph_id=context.graph_id,
            node_id=context.node_id,
            parent_event_id=context.parent_event_id,
            ts_ms=self._now_ms(),
            payload=payload,
        )
        if self._event_sink is not None:
            self._event_sink(event)
        return event

    def _compute_idempotency_key(
        self, context: ExecutionContext, tool_call: ToolCall
    ) -> str:
        if context.idempotency_key is not None:
            return context.idempotency_key
        return compute_hash_dict(
            {
                "execution_identity": context.execution_identity,
                "actor": context.actor,
                "graph_id": context.graph_id,
                "node_id": context.node_id,
                "artifact_refs": context.artifact_refs,
                "tool_name": tool_call.name,
                "params": tool_call.params,
                "state_ref": context.state_ref,
            }
        )

    def _build_execution_identity(
        self,
        *,
        context: ExecutionContext,
        tool_call: ToolCall,
    ) -> ExecutionIdentity:
        input_hashes = tuple(
            sorted(
                h for h in context.metadata.get("input_hashes", "").split(",") if h
            )
        )
        value = compute_hash_dict(
            {
                "trace_id": context.trace_id,
                "graph_id": context.graph_id,
                "node_id": context.node_id,
                "tool_name": tool_call.name,
                "tool_params": tool_call.params,
                "input_hashes": input_hashes,
                "policy_snapshot": context.policy_snapshot,
                "strategy_snapshot": context.strategy_snapshot,
            }
        )
        return ExecutionIdentity(
            value=value,
            node_id=context.node_id,
            graph_id=context.graph_id,
            tool_name=tool_call.name,
        )

    def execute(
        self,
        tool_call: ToolCall,
        context: ExecutionContext,
        *,
        authorised_params: Optional[dict] = None,
        authorised_tool_name: Optional[str] = None,
    ) -> RuntimeExecutionResult:
        """Execute a tool call through the canonical runtime boundary."""
        execution_identity = self._build_execution_identity(
            context=context,
            tool_call=tool_call,
        )
        effective_context = ExecutionContext(
            trace_id=context.trace_id,
            execution_identity=execution_identity.value,
            actor=context.actor,
            state_ref=context.state_ref,
            policy_ref=context.policy_ref,
            graph_id=context.graph_id,
            node_id=context.node_id,
            strategy_snapshot=context.strategy_snapshot,
            budget_ref=context.budget_ref,
            memory_ref=context.memory_ref,
            artifact_refs=context.artifact_refs,
            parent_event_id=context.parent_event_id,
            causal_chain=context.causal_chain,
            policy_snapshot=context.policy_snapshot,
            idempotency_key=context.idempotency_key,
            max_time_ms=context.max_time_ms,
            max_calls=context.max_calls,
            call_index=context.call_index,
            metadata=context.metadata,
        )

        self._emit(
            "task.started",
            effective_context,
            {"tool_name": tool_call.name, "actor": context.actor},
        )

        if (
            effective_context.max_calls is not None
            and effective_context.call_index > effective_context.max_calls
        ):
            denied = RuntimeExecutionResult(
                dispatcher_result=ExecutionResult(
                    success=False,
                    tool_name=tool_call.name,
                    error=(
                        f"Call budget exceeded: call_index={effective_context.call_index} > "
                        f"max_calls={effective_context.max_calls}"
                    ),
                ),
                trace_id=effective_context.trace_id,
                elapsed_ms=0,
                budget_exceeded=True,
            )
            self._emit(
                "error.raised",
                effective_context,
                {"error": denied.dispatcher_result.error or "UNKNOWN"},
            )
            return denied

        idempotency_key = self._compute_idempotency_key(effective_context, tool_call)
        if idempotency_key in self._result_cache:
            cached = self._result_cache[idempotency_key]
            record = self._idempotency_store.get(idempotency_key)
            replayed = RuntimeExecutionResult(
                dispatcher_result=cached.dispatcher_result,
                trace_id=effective_context.trace_id,
                elapsed_ms=0,
                budget_exceeded=cached.budget_exceeded,
                denied_by_hook=cached.denied_by_hook,
                deduplicated=True,
            )
            self._emit(
                "tool.deduplicated",
                effective_context,
                {
                    "tool_name": tool_call.name,
                    "idempotency_key": idempotency_key,
                    "output_hash": record.output_hash if record else "unknown",
                },
            )
            return replayed

        if self._before_execute is not None:
            denial_reason = self._before_execute(effective_context, tool_call)
            if denial_reason:
                denied = RuntimeExecutionResult(
                    dispatcher_result=ExecutionResult(
                        success=False,
                        tool_name=tool_call.name,
                        error=f"Execution denied by hook: {denial_reason}",
                    ),
                    trace_id=effective_context.trace_id,
                    elapsed_ms=0,
                    budget_exceeded=False,
                    denied_by_hook=True,
                )
                self._emit(
                    "policy.denied",
                    effective_context,
                    {"reason": denial_reason},
                )
                if self._on_error is not None:
                    self._on_error(effective_context, tool_call, denied)
                return denied

        self._emit("tool.called", effective_context, {"tool_name": tool_call.name})
        start = perf_counter()
        dispatcher_result = self._dispatcher.execute(
            tool_call,
            authorised_params=authorised_params,
            authorised_tool_name=authorised_tool_name,
        )
        elapsed_ms = int((perf_counter() - start) * 1000)

        budget_exceeded = (
            effective_context.max_time_ms is not None
            and elapsed_ms > effective_context.max_time_ms
        )
        if budget_exceeded and dispatcher_result.success:
            dispatcher_result = ExecutionResult(
                success=False,
                tool_name=tool_call.name,
                error=(
                    f"Execution budget exceeded: {elapsed_ms}ms > "
                    f"{effective_context.max_time_ms}ms"
                ),
            )

        result = RuntimeExecutionResult(
            dispatcher_result=dispatcher_result,
            trace_id=effective_context.trace_id,
            elapsed_ms=elapsed_ms,
            budget_exceeded=budget_exceeded,
        )
        if result.dispatcher_result.success:
            self._result_cache[idempotency_key] = result
            self._idempotency_store.put(
                IdempotencyRecord(
                    key=idempotency_key,
                    input_hash=compute_hash_dict(
                        {
                            "tool_name": tool_call.name,
                            "tool_params": tool_call.params,
                            "execution_identity": effective_context.execution_identity,
                        }
                    ),
                    output_hash=compute_hash_dict(
                        {"result": result.dispatcher_result.result}
                    ),
                    tool_name=tool_call.name,
                    ts_ms=self._now_ms(),
                )
            )
            self._emit(
                "tool.completed",
                effective_context,
                {"tool_name": tool_call.name},
            )
            self._emit(
                "task.completed",
                effective_context,
                {"tool_name": tool_call.name},
            )
        else:
            self._emit(
                "error.raised",
                effective_context,
                {"error": result.dispatcher_result.error or "UNKNOWN"},
            )
            if self._on_error is not None:
                self._on_error(effective_context, tool_call, result)

        if self._after_execute is not None:
            self._after_execute(effective_context, tool_call, result)

        return result

    def _resolve_execution_order(self, graph: TaskGraph) -> tuple[str, ...]:
        """Resolve deterministic topological order for graph nodes."""
        nodes_by_id = {node.node_id: node for node in graph.nodes}
        if len(nodes_by_id) != len(graph.nodes):
            raise ValueError("Graph contains duplicate node IDs")

        for node in graph.nodes:
            for dependency_id in node.depends_on:
                if dependency_id not in nodes_by_id:
                    raise ValueError(
                        f"Graph node '{node.node_id}' depends on unknown node "
                        f"'{dependency_id}'"
                    )

        visited: set[str] = set()
        visiting: set[str] = set()
        order: list[str] = []

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            if node_id in visiting:
                raise ValueError(f"Graph cycle detected at node '{node_id}'")

            visiting.add(node_id)
            node = nodes_by_id[node_id]
            for dep_id in sorted(node.depends_on):
                visit(dep_id)
            visiting.remove(node_id)
            visited.add(node_id)
            order.append(node_id)

        for node_id in sorted(nodes_by_id.keys()):
            visit(node_id)

        return tuple(order)

    def execute_graph(
        self, graph: TaskGraph, context: ExecutionContext
    ) -> GraphExecutionResult:
        """Execute a deterministic DAG of tool calls."""
        self._emit(
            "graph.started",
            context,
            {"graph_id": graph.graph_id, "node_count": str(len(graph.nodes))},
        )
        nodes_by_id = {node.node_id: node for node in graph.nodes}
        order = self._resolve_execution_order(graph)
        budget = GraphBudget(
            total_calls=context.max_calls if context.max_calls is not None else len(order),
            remaining_calls=context.max_calls
            if context.max_calls is not None
            else len(order),
        )
        results: dict[str, RuntimeExecutionResult] = {}
        produced_artifacts: dict[str, Artifact] = {}
        produced_by_node: dict[str, str] = {}

        for index, node_id in enumerate(order, start=1):
            node = nodes_by_id[node_id]
            if budget.remaining_calls <= 0:
                self._emit(
                    "graph.failed",
                    context,
                    {
                        "graph_id": graph.graph_id,
                        "failed_node": node_id,
                        "error": "Graph call budget exhausted",
                    },
                )
                return GraphExecutionResult(
                    trace_id=context.trace_id,
                    node_results=results,
                    execution_order=tuple(results.keys()),
                    output_artifacts=produced_artifacts,
                    success=False,
                    error="Graph call budget exhausted",
                )
            self._emit(
                "node.scheduled",
                context,
                {"graph_id": graph.graph_id, "node_id": node_id},
            )
            parent_event_id = None
            if node.depends_on:
                parent_event_id = compute_hash_dict(
                    {
                        "trace_id": context.trace_id,
                        "graph_id": graph.graph_id,
                        "node": sorted(node.depends_on),
                    }
                )

            input_artifact_ids: list[str] = []
            input_hashes: list[str] = []
            for artifact_ref in node.input_artifacts:
                artifact_lookup_id = artifact_ref.artifact_id
                if artifact_lookup_id.startswith("node:"):
                    source_node_id = artifact_lookup_id.split(":", 1)[1]
                    artifact_lookup_id = produced_by_node.get(source_node_id, "")

                artifact = self._artifact_store.get(artifact_lookup_id)
                if artifact is None:
                    self._emit(
                        "node.failed",
                        context,
                        {
                            "graph_id": graph.graph_id,
                            "node_id": node_id,
                            "error": (
                                f"Missing input artifact: "
                                f"{artifact_ref.artifact_id}"
                            ),
                        },
                    )
                    return GraphExecutionResult(
                        trace_id=context.trace_id,
                        node_results=results,
                        execution_order=tuple(results.keys()),
                        output_artifacts=produced_artifacts,
                        success=False,
                        error=f"Missing input artifact: {artifact_ref.artifact_id}",
                    )
                if (
                    artifact_ref.required_type is not None
                    and artifact.artifact_type != artifact_ref.required_type
                ):
                    self._emit(
                        "node.failed",
                        context,
                        {
                            "graph_id": graph.graph_id,
                            "node_id": node_id,
                            "error": (
                                "Artifact type mismatch for "
                                f"{artifact_ref.artifact_id}"
                            ),
                        },
                    )
                    return GraphExecutionResult(
                        trace_id=context.trace_id,
                        node_results=results,
                        execution_order=tuple(results.keys()),
                        output_artifacts=produced_artifacts,
                        success=False,
                        error=(
                            "Artifact type mismatch for "
                            f"{artifact_ref.artifact_id}"
                        ),
                    )
                if (
                    artifact_ref.required_schema_version is not None
                    and artifact.schema_version
                    != artifact_ref.required_schema_version
                ):
                    self._emit(
                        "node.failed",
                        context,
                        {
                            "graph_id": graph.graph_id,
                            "node_id": node_id,
                            "error": (
                                "Artifact schema mismatch for "
                                f"{artifact_ref.artifact_id}"
                            ),
                        },
                    )
                    return GraphExecutionResult(
                        trace_id=context.trace_id,
                        node_results=results,
                        execution_order=tuple(results.keys()),
                        output_artifacts=produced_artifacts,
                        success=False,
                        error=(
                            "Artifact schema mismatch for "
                            f"{artifact_ref.artifact_id}"
                        ),
                    )
                input_artifact_ids.append(artifact.artifact_id)
                input_hashes.append(artifact.value_hash)

            self._emit(
                "node.started",
                context,
                {"graph_id": graph.graph_id, "node_id": node_id},
            )
            node_context = ExecutionContext(
                trace_id=context.trace_id,
                execution_identity=None,
                graph_id=graph.graph_id,
                node_id=node_id,
                actor=context.actor,
                state_ref=context.state_ref,
                policy_ref=context.policy_ref,
                strategy_snapshot=context.strategy_snapshot,
                budget_ref=context.budget_ref,
                memory_ref=context.memory_ref,
                artifact_refs=tuple(sorted(input_artifact_ids)),
                parent_event_id=parent_event_id,
                causal_chain=context.causal_chain + (node_id,),
                policy_snapshot=context.policy_snapshot,
                idempotency_key=None,
                max_time_ms=context.max_time_ms,
                max_calls=context.max_calls,
                call_index=index,
                metadata={
                    **context.metadata,
                    "input_hashes": ",".join(sorted(input_hashes)),
                    "budget_remaining_calls": str(budget.remaining_calls),
                },
            )

            node_result = self.execute(node.tool_call, node_context)
            results[node_id] = node_result
            budget = GraphBudget(
                total_calls=budget.total_calls,
                remaining_calls=max(0, budget.remaining_calls - 1),
            )
            if not node_result.dispatcher_result.success:
                self._emit(
                    "graph.failed",
                    context,
                    {
                        "graph_id": graph.graph_id,
                        "failed_node": node_id,
                        "error": node_result.dispatcher_result.error or "UNKNOWN",
                    },
                )
                return GraphExecutionResult(
                    trace_id=context.trace_id,
                    node_results=results,
                    execution_order=tuple(results.keys()),
                    output_artifacts=produced_artifacts,
                    success=False,
                    error=node_result.dispatcher_result.error,
                )
            self._emit(
                "node.completed",
                context,
                {"graph_id": graph.graph_id, "node_id": node_id},
            )
            artifact_event = self._emit(
                "artifact.created",
                node_context,
                {"graph_id": graph.graph_id, "node_id": node_id},
            )
            stored_artifact = self._artifact_store.put(
                artifact_id=None,
                artifact_type=node.output_artifact_type,
                schema_version=node.output_schema_version,
                value=node_result.dispatcher_result.result,
                provenance=(graph.graph_id, node_id),
                created_event_id=artifact_event.event_id,
                parent_artifacts=tuple(sorted(input_artifact_ids)),
            )
            produced_artifacts[stored_artifact.artifact_id] = Artifact(
                artifact_id=stored_artifact.artifact_id,
                artifact_type=stored_artifact.artifact_type,
                schema_version=stored_artifact.schema_version,
                value=stored_artifact.value,
                value_hash=stored_artifact.value_hash,
                provenance=stored_artifact.provenance,
                created_event_id=stored_artifact.created_event_id,
                parent_artifacts=stored_artifact.parent_artifacts,
            )
            produced_by_node[node_id] = stored_artifact.artifact_id
            self._emit(
                "dependency.resolved",
                context,
                {
                    "graph_id": graph.graph_id,
                    "node_id": node_id,
                    "artifact_id": stored_artifact.artifact_id,
                },
            )

        self._emit(
            "graph.completed",
            context,
            {"graph_id": graph.graph_id, "node_count": str(len(order))},
        )
        return GraphExecutionResult(
            trace_id=context.trace_id,
            node_results=results,
            execution_order=order,
            output_artifacts=produced_artifacts,
            success=True,
        )
