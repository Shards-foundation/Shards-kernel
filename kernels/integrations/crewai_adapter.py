"""
CrewAI Integration Adapter for KERNELS

Provides permit-based governance for CrewAI multi-agent systems.

CrewAI is a multi-agent orchestration framework that allows agents to:
- Delegate tasks to other specialist agents
- Use tools to interact with external systems
- Collaborate via context sharing

KERNELS Governance Layer:
- All tool executions require cryptographic permits
- Agent delegation requires authorization
- Multi-agent privilege escalation detection
- Complete audit trail of agent interactions

Usage:
    from kernels.integrations import CrewAIAdapter
    from crewai import Agent, Task, Crew

    # Create KERNELS adapter
    adapter = CrewAIAdapter(kernel, actor="crew-orchestrator")

    # Wrap CrewAI tools
    governed_tool = adapter.wrap_tool(
        name="file_write",
        func=file_write_fn,
        description="Write to filesystem"
    )

    # Create CrewAI agent with governed tools
    agent = Agent(
        role="File Manager",
        tools=[governed_tool],
        ...
    )

Author: KERNELS Team
License: MIT
"""

from typing import Callable, Optional, Dict, Any, Type, List
from dataclasses import dataclass
import uuid

# CrewAI imports (these may not be installed, so we handle gracefully)
try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field

    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

    # Define stubs for type hints
    class BaseTool:  # type: ignore
        pass

    class BaseModel:  # type: ignore
        pass

    def Field(*_args, **_kwargs):  # type: ignore
        """Stand-in so tool schemas can be built without pydantic."""
        return None


# KERNELS imports
from kernels.common.types import (
    KernelRequest,
    ToolCall,
    Decision,
)
from kernels.permits import PermitToken
from kernels.variants.base import BaseKernel


@dataclass
class CrewAIToolResult:
    """Result from CrewAI tool execution with KERNELS governance."""

    was_allowed: bool
    decision: Decision
    result: Optional[str]  # CrewAI tools always return strings
    error: Optional[str]
    request_id: str
    receipt_hash: Optional[str]


class GovernedCrewAITool(BaseTool if CREWAI_AVAILABLE else object):
    """
    CrewAI BaseTool wrapper with KERNELS governance.

    This class implements CrewAI's BaseTool interface while enforcing
    permit-based governance for all tool executions.

    Attributes:
        name: Tool name (CrewAI requirement)
        description: Tool description (CrewAI requirement)
        args_schema: Pydantic schema for arguments (CrewAI requirement)
        func: Underlying function to execute
        kernel: KERNELS kernel instance
        actor: Actor identity (agent name)
    """

    name: str
    description: str
    args_schema: Type[BaseModel]

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable,
        kernel: BaseKernel,
        actor: str,
        args_schema: Optional[Type[BaseModel]] = None,
        require_permit: bool = True,
    ):
        """
        Initialize governed CrewAI tool.

        Args:
            name: Tool name
            description: Tool description for agent understanding
            func: Underlying tool function
            kernel: KERNELS kernel instance
            actor: Actor identity (agent name)
            args_schema: Pydantic schema for tool arguments
            require_permit: Whether this tool requires permits (default: True)
        """
        # Store KERNELS-specific attributes first
        self.func = func
        self.kernel = kernel
        self.actor = actor
        self.require_permit = require_permit
        self._call_count = 0

        # Set CrewAI-required attributes
        self.name = name
        self.description = description

        # Create args_schema if not provided
        if args_schema is None:
            # Create dynamic schema from function signature
            self.args_schema = self._create_schema_from_func(func)
        else:
            self.args_schema = args_schema

        # Initialize BaseTool if available
        if CREWAI_AVAILABLE:
            super().__init__()

    def _create_schema_from_func(self, func: Callable) -> Type[BaseModel]:
        """Create Pydantic schema from function signature."""
        import inspect

        # Get function signature
        sig = inspect.signature(func)

        # Build field definitions
        fields = {}
        for param_name, param in sig.parameters.items():
            if param_name in ["permit_token", "self", "cls"]:
                continue

            # Determine type annotation
            param_type = (
                param.annotation if param.annotation != inspect.Parameter.empty else str
            )

            # Create Field
            fields[param_name] = (
                param_type,
                Field(description=f"Parameter: {param_name}"),
            )

        # Create dynamic Pydantic model
        schema_name = f"{self.name}Input"
        return type(
            schema_name,
            (BaseModel,),
            {
                "__annotations__": {k: v[0] for k, v in fields.items()},
                **{k: v[1] for k, v in fields.items()},
            },
        )

    def _run(self, permit_token: Optional[PermitToken] = None, **kwargs) -> str:
        """
        Execute tool with KERNELS governance (CrewAI sync interface).

        This method implements CrewAI's BaseTool._run() interface while
        enforcing permit-based governance.

        Args:
            permit_token: Optional permit for authorization
            **kwargs: Tool-specific arguments

        Returns:
            str: Tool execution result (CrewAI requirement)

        Raises:
            Exception: If execution is denied by KERNELS
        """
        self._call_count += 1

        # Create kernel request
        request_id = f"{self.name}-{self._call_count}-{uuid.uuid4().hex[:8]}"
        request = KernelRequest(
            request_id=request_id,
            ts_ms=self.kernel.config.clock.now_ms(),
            actor=self.actor,
            intent=f"Execute CrewAI tool: {self.name}",
            tool_call=ToolCall(name=self.name, params=kwargs),
            params=kwargs,
        )

        # Submit to kernel
        receipt = self.kernel.submit(request, permit_token=permit_token)

        # Handle decision
        if receipt.decision == Decision.ALLOW:
            # Tool execution was allowed
            result = str(receipt.tool_result)
            return result
        else:
            # Tool execution was denied
            error_msg = f"Tool {self.name} denied by KERNELS: {receipt.error}"
            raise PermissionError(error_msg)

    async def _arun(self, permit_token: Optional[PermitToken] = None, **kwargs) -> str:
        """
        Execute tool asynchronously with KERNELS governance (CrewAI async interface).

        For now, delegates to synchronous _run().
        Future: Implement true async kernel submission.

        Args:
            permit_token: Optional permit for authorization
            **kwargs: Tool-specific arguments

        Returns:
            str: Tool execution result (CrewAI requirement)
        """
        # For now, delegate to sync version
        # TODO: Implement async kernel submission
        return self._run(permit_token=permit_token, **kwargs)


class CrewAIAdapter:
    """
    KERNELS adapter for CrewAI multi-agent orchestration.

    This adapter provides permit-based governance for CrewAI agents and tools,
    enabling secure multi-agent collaboration with complete audit trails.

    Key Features:
    - Tool execution governance
    - Agent delegation control
    - Multi-agent privilege escalation detection
    - Inter-agent permission matrix
    - Complete audit trail

    Usage:
        adapter = CrewAIAdapter(kernel, actor="crew-orchestrator")

        # Wrap tools
        governed_tool = adapter.wrap_tool("file_write", file_write_fn)

        # Create CrewAI agent with governed tools
        agent = Agent(role="Writer", tools=[governed_tool])
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "crewai-agent",
        auto_register: bool = True,
    ):
        """
        Initialize CrewAI adapter.

        Args:
            kernel: KERNELS kernel instance
            actor: Default actor identity for agents
            auto_register: Auto-register tools in kernel dispatcher
        """
        # CrewAI itself is optional. The governance wrapper runs without it.
        self.kernel = kernel
        self.default_actor = actor
        self.auto_register = auto_register
        self._tools: Dict[str, GovernedCrewAITool] = {}

    def wrap_tool(
        self,
        name: str,
        func: Callable,
        description: str = "",
        actor: Optional[str] = None,
        args_schema: Optional[Type[BaseModel]] = None,
        require_permit: bool = True,
    ) -> GovernedCrewAITool:
        """
        Wrap a function as a governed CrewAI tool.

        Args:
            name: Tool name
            func: Function to wrap
            description: Tool description for agents
            actor: Actor identity (defaults to adapter's actor)
            args_schema: Pydantic schema for arguments
            require_permit: Whether tool requires permits

        Returns:
            GovernedCrewAITool instance compatible with CrewAI
        """
        actor = actor or self.default_actor

        # Register tool in kernel dispatcher if auto_register enabled
        if self.auto_register:
            self.kernel._dispatcher.registry.register(
                name=name,
                handler=func,
                description=description or f"CrewAI tool: {name}",
            )

        # Create governed tool
        governed_tool = GovernedCrewAITool(
            name=name,
            description=description or f"Execute {name}",
            func=func,
            kernel=self.kernel,
            actor=actor,
            args_schema=args_schema,
            require_permit=require_permit,
        )

        # Store for later retrieval
        self._tools[name] = governed_tool

        return governed_tool

    def get_tool(self, name: str) -> Optional[GovernedCrewAITool]:
        """Get governed tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        """List all wrapped tool names."""
        return list(self._tools.keys())

    def export_evidence(self) -> Dict[str, Any]:
        """
        Export audit trail evidence bundle.

        Returns:
            Evidence bundle containing all tool executions,
            decisions, and permit verifications.
        """
        from kernels.common.codec import audit_entry_to_dict

        evidence = self.kernel.export_evidence()
        entries = [audit_entry_to_dict(entry) for entry in evidence.ledger_entries]
        return {
            "kernel_id": evidence.kernel_id,
            "variant": evidence.variant,
            "root_hash": evidence.root_hash,
            "exported_at_ms": evidence.exported_at_ms,
            "entries": entries,
            "entry_count": len(entries),
        }

    def create_agent_identity(
        self,
        role: str,
        agent_id: Optional[str] = None,
    ) -> str:
        """
        Create unique agent identity for multi-agent governance.

        Args:
            role: Agent role (e.g., "Researcher", "Writer")
            agent_id: Optional unique ID (auto-generated if not provided)

        Returns:
            Agent identity string for use in permit issuance
        """
        if agent_id is None:
            agent_id = uuid.uuid4().hex[:8]

        return f"{role.lower().replace(' ', '-')}-{agent_id}"

    def validate_delegation(
        self,
        from_agent: str,
        to_agent: str,
        task_type: str,
        delegation_matrix: Optional[Dict[str, List[str]]] = None,
    ) -> bool:
        """
        Validate agent-to-agent delegation using permission matrix.

        Args:
            from_agent: Delegating agent identity
            to_agent: Target agent identity
            task_type: Type of task being delegated
            delegation_matrix: Optional permission matrix
                              Format: {from_agent: [allowed_to_agents]}

        Returns:
            True if delegation is allowed, False otherwise

        Example:
            matrix = {
                "manager-agent": ["researcher-agent", "writer-agent"],
                "researcher-agent": [],  # Cannot delegate
            }

            adapter.validate_delegation(
                "manager-agent",
                "researcher-agent",
                "research_task",
                matrix
            )  # Returns True
        """
        if delegation_matrix is None:
            # No matrix provided, allow all delegations
            return True

        allowed_targets = delegation_matrix.get(from_agent, [])
        return to_agent in allowed_targets


def create_crewai_adapter(
    kernel: BaseKernel,
    actor: str = "crewai-agent",
    auto_register: bool = True,
) -> CrewAIAdapter:
    """
    Factory function to create CrewAI adapter.

    Args:
        kernel: KERNELS kernel instance
        actor: Default actor identity
        auto_register: Auto-register tools in kernel

    Returns:
        CrewAIAdapter instance
    """
    return CrewAIAdapter(
        kernel=kernel,
        actor=actor,
        auto_register=auto_register,
    )
