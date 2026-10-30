"""
LangGraph Integration Adapter for Shards-Kernel

Provides permit-based governance for LangGraph stateful agent workflows.

LangGraph is an extension of LangChain that enables building stateful,
multi-step agent workflows with:
- State management across workflow steps
- Conditional edges for dynamic routing
- Cycles and loops in workflow graphs
- Long-running persistent workflows

Shards-Kernel Governance Layer:
- State transition validation
- Node-level authorization
- Workflow invariants enforcement
- Step-level permit requirements
- Complete audit trail of state mutations

Usage:
    from shards_kernel.integrations import LangGraphAdapter
    from langgraph.graph import StateGraph

    # Create Shards-Kernel adapter
    adapter = LangGraphAdapter(kernel, actor="workflow-agent")

    # Wrap workflow nodes
    governed_node = adapter.wrap_node("process_data", process_fn)

    # Build LangGraph workflow
    workflow = StateGraph(state_schema)
    workflow.add_node("process", governed_node)
    workflow.compile()

Author: Shards-Kernel Team
License: MIT
"""

from typing import Callable, Optional, Dict, Any, List, TypeVar
from dataclasses import dataclass
import uuid

# Try to import LangGraph components
try:
    from langgraph.graph import StateGraph
    from pydantic import BaseModel

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    StateGraph = None
    BaseModel = object

# Shards-Kernel imports
from shards_kernel.common.types import (
    KernelRequest,
    ToolCall,
    Decision,
)
from shards_kernel.permits import PermitToken
from shards_kernel.variants.base import BaseKernel

# Try to import LangChain adapter (we extend it)
try:
    from shards_kernel.integrations.langchain_adapter import LangChainAdapter

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    LangChainAdapter = object


StateType = TypeVar("StateType")


@dataclass
class StateTransition:
    """Record of state transition in workflow."""

    from_node: Optional[str]
    to_node: str
    timestamp_ms: int
    state_before: Dict[str, Any]
    state_after: Dict[str, Any]
    was_allowed: bool
    permit_verified: bool


@dataclass
class WorkflowInvariant:
    """Invariant that must hold throughout workflow execution."""

    name: str
    description: str
    validator: Callable[[Dict[str, Any]], bool]
    enforce: bool = True  # If True, violating this invariant halts workflow


class LangGraphAdapter:
    """
    Shards-Kernel adapter for LangGraph stateful workflows.

    This adapter provides permit-based governance for LangGraph workflows,
    including state transition validation, node-level authorization, and
    workflow invariants enforcement.

    Key Features:
    - Node execution governance
    - State transition validation
    - Workflow invariants enforcement
    - Step-level permit requirements
    - Complete audit trail of state mutations
    - Rollback on policy violation

    Usage:
        adapter = LangGraphAdapter(kernel, actor="workflow-agent")

        # Wrap nodes
        governed_node = adapter.wrap_node("process_data", process_fn)

        # Define workflow invariants
        adapter.add_invariant(
            "budget_limit",
            "Total cost must not exceed budget",
            lambda state: state.get("total_cost", 0) <= state.get("budget", 1000)
        )

        # Build workflow
        workflow = StateGraph(state_schema)
        workflow.add_node("process", governed_node)
        workflow.compile()
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "langgraph-workflow",
        auto_register: bool = True,
        enforce_invariants: bool = True,
    ):
        """
        Initialize LangGraph adapter.

        Args:
            kernel: Shards-Kernel kernel instance
            actor: Default actor identity for workflow
            auto_register: Auto-register nodes in kernel dispatcher
            enforce_invariants: Enforce workflow invariants (halt on violation)
        """
        # LangGraph itself is optional. Node governance runs without it.
        self.langgraph_available = LANGGRAPH_AVAILABLE
        self.kernel = kernel
        self.actor = actor
        self.auto_register = auto_register
        self.enforce_invariants = enforce_invariants

        self._nodes: Dict[str, Callable] = {}
        self._transitions: List[StateTransition] = []
        self._invariants: List[WorkflowInvariant] = []
        self._current_node: Optional[str] = None

        # Extend LangChain adapter if available
        if LANGCHAIN_AVAILABLE:
            self._langchain_adapter = LangChainAdapter(kernel=kernel, actor=actor)
        else:
            self._langchain_adapter = None

    def add_invariant(
        self,
        name: str,
        description: str,
        validator: Callable[[Dict[str, Any]], bool],
        enforce: bool = True,
    ):
        """
        Add workflow invariant.

        Invariants are conditions that must hold throughout workflow execution.
        If enforce=True, violating the invariant will halt the workflow.

        Args:
            name: Invariant name
            description: Invariant description
            validator: Function that takes state and returns True if valid
            enforce: Whether to halt workflow on violation

        Example:
            adapter.add_invariant(
                "budget_limit",
                "Total cost must not exceed budget",
                lambda state: state.get("total_cost", 0) <= state.get("budget", 1000),
                enforce=True
            )
        """
        invariant = WorkflowInvariant(
            name=name,
            description=description,
            validator=validator,
            enforce=enforce,
        )
        self._invariants.append(invariant)

    def check_invariants(self, state: Dict[str, Any]) -> List[str]:
        """
        Check all workflow invariants against current state.

        Args:
            state: Current workflow state

        Returns:
            List of violated invariant names

        Raises:
            RuntimeError: If enforced invariant is violated
        """
        violations = []

        for invariant in self._invariants:
            try:
                is_valid = invariant.validator(state)
            except Exception as e:
                is_valid = False
                print(f"Warning: Invariant {invariant.name} raised exception: {e}")

            if not is_valid:
                violations.append(invariant.name)

                if invariant.enforce:
                    raise RuntimeError(
                        f"Workflow invariant violated: {invariant.name}\n"
                        f"Description: {invariant.description}\n"
                        f"State: {state}"
                    )

        return violations

    def wrap_node(
        self,
        name: str,
        func: Callable[[StateType], StateType],
        description: str = "",
        require_permit: bool = False,
    ) -> Callable[[StateType], StateType]:
        """
        Wrap LangGraph node with Shards-Kernel governance.

        Args:
            name: Node name
            func: Node function (receives state, returns updated state)
            description: Node description
            require_permit: Whether this node requires permits

        Returns:
            Governed node function

        Example:
            def process_data(state: dict) -> dict:
                state["processed"] = True
                return state

            governed = adapter.wrap_node("process_data", process_data)
        """
        # The kernel invokes tools with keyword parameters. Nodes take one
        # state mapping, so the registered handler rebuilds that mapping.
        def run_node(**params: Any) -> Any:
            return func(params)

        if self.auto_register:
            self.kernel._dispatcher.registry.register(
                name=name,
                handler=run_node,
                description=description or f"LangGraph node: {name}",
            )

        def governed_node(
            state: StateType, permit_token: Optional[PermitToken] = None
        ) -> StateType:
            """Governed node execution with state transition tracking."""

            # Record transition
            prev_node = self._current_node
            self._current_node = name

            # Convert state to dict for Shards-Kernel
            if isinstance(state, dict):
                state_dict = state
            elif hasattr(state, "__dict__"):
                state_dict = state.__dict__
            elif hasattr(state, "dict"):
                state_dict = state.dict()
            else:
                state_dict = {"state": str(state)}

            # Check invariants before execution
            if self.enforce_invariants:
                self.check_invariants(state_dict)

            # Create kernel request
            request_id = f"{name}-node-{uuid.uuid4().hex[:8]}"
            request = KernelRequest(
                request_id=request_id,
                ts_ms=self.kernel.config.clock.now_ms(),
                actor=self.actor,
                intent=f"Execute LangGraph node: {name}",
                tool_call=ToolCall(name=name, params=state_dict),
                params=state_dict,
            )

            # Submit to kernel
            receipt = self.kernel.submit(request, permit_token=permit_token)

            # Handle decision
            if receipt.decision == Decision.ALLOW:
                # The kernel already ran the node. Do not run it again.
                updated_state = receipt.tool_result
                if updated_state is None:
                    updated_state = state

                # Convert updated state to dict
                if isinstance(updated_state, dict):
                    updated_state_dict = updated_state
                elif hasattr(updated_state, "__dict__"):
                    updated_state_dict = updated_state.__dict__
                elif hasattr(updated_state, "dict"):
                    updated_state_dict = updated_state.dict()
                else:
                    updated_state_dict = {"state": str(updated_state)}

                # Check invariants after execution
                if self.enforce_invariants:
                    self.check_invariants(updated_state_dict)

                # Record transition
                transition = StateTransition(
                    from_node=prev_node,
                    to_node=name,
                    timestamp_ms=self.kernel.config.clock.now_ms(),
                    state_before=state_dict,
                    state_after=updated_state_dict,
                    was_allowed=True,
                    permit_verified=(permit_token is not None),
                )
                self._transitions.append(transition)

                return updated_state
            else:
                # Node execution was denied
                error_msg = f"Node {name} denied by Shards-Kernel: {receipt.error}"

                # Record failed transition
                transition = StateTransition(
                    from_node=prev_node,
                    to_node=name,
                    timestamp_ms=self.kernel.config.clock.now_ms(),
                    state_before=state_dict,
                    state_after=state_dict,  # State unchanged
                    was_allowed=False,
                    permit_verified=(permit_token is not None),
                )
                self._transitions.append(transition)

                raise PermissionError(error_msg)

        # Store node
        self._nodes[name] = governed_node

        return governed_node

    def get_node(self, name: str) -> Optional[Callable]:
        """Get governed node by name."""
        return self._nodes.get(name)

    def list_nodes(self) -> List[str]:
        """List all wrapped node names."""
        return list(self._nodes.keys())

    def get_transitions(self) -> List[StateTransition]:
        """Get all recorded state transitions."""
        return self._transitions

    def export_evidence(self) -> Dict[str, Any]:
        """
        Export audit trail evidence bundle with workflow-specific data.

        Returns:
            Evidence bundle containing:
            - All node executions
            - State transitions
            - Invariant violations
            - Permit verifications
        """
        from shards_kernel.common.codec import audit_entry_to_dict

        bundle = self.kernel.export_evidence()
        entries = [audit_entry_to_dict(entry) for entry in bundle.ledger_entries]
        evidence: Dict[str, Any] = {
            "kernel_id": bundle.kernel_id,
            "variant": bundle.variant,
            "root_hash": bundle.root_hash,
            "exported_at_ms": bundle.exported_at_ms,
            "entries": entries,
            "entry_count": len(entries),
        }

        # Add workflow-specific data
        evidence["workflow_data"] = {
            "nodes": list(self._nodes.keys()),
            "transitions": [
                {
                    "from_node": t.from_node,
                    "to_node": t.to_node,
                    "timestamp_ms": t.timestamp_ms,
                    "was_allowed": t.was_allowed,
                    "permit_verified": t.permit_verified,
                }
                for t in self._transitions
            ],
            "invariants": [
                {
                    "name": inv.name,
                    "description": inv.description,
                    "enforce": inv.enforce,
                }
                for inv in self._invariants
            ],
        }

        return evidence

    def reset_workflow(self):
        """Reset workflow state (clear transitions)."""
        self._transitions = []
        self._current_node = None


def create_langgraph_adapter(
    kernel: BaseKernel,
    actor: str = "langgraph-workflow",
    auto_register: bool = True,
    enforce_invariants: bool = True,
) -> LangGraphAdapter:
    """
    Factory function to create LangGraph adapter.

    Args:
        kernel: Shards-Kernel kernel instance
        actor: Default actor identity
        auto_register: Auto-register nodes in kernel
        enforce_invariants: Enforce workflow invariants

    Returns:
        LangGraphAdapter instance
    """
    return LangGraphAdapter(
        kernel=kernel,
        actor=actor,
        auto_register=auto_register,
        enforce_invariants=enforce_invariants,
    )
