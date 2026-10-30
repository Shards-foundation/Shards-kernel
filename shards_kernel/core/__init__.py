"""Core runtime primitives.

This package contains the canonical runtime execution choke point used by
kernel variants to mediate tool execution through a single interface.
"""

from shards_kernel.core.runtime import (
    Artifact,
    ArtifactRef,
    ExecutionIdentity,
    ExecutionContext,
    GraphBudget,
    GraphExecutionResult,
    RuntimeState,
    TaskGraph,
    TaskNode,
    RuntimeEvent,
    RuntimeExecutionResult,
    KernelRuntime,
)

__all__ = [
    "ExecutionContext",
    "ExecutionIdentity",
    "GraphBudget",
    "ArtifactRef",
    "Artifact",
    "TaskNode",
    "TaskGraph",
    "GraphExecutionResult",
    "RuntimeState",
    "RuntimeEvent",
    "RuntimeExecutionResult",
    "KernelRuntime",
]
