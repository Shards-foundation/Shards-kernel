"""
Shards-Kernel Hugging Face Integration

Adapter for Hugging Face Transformers Agents with permit-based governance.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable

from shards_kernel.common.types import KernelRequest, ToolCall, Decision
from shards_kernel.variants.base import BaseKernel
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.permits import PermitToken
from shards_kernel.common.errors import PermitError


@dataclass
class HFToolResult:
    """Result from a governed Hugging Face tool execution."""

    tool_name: str
    result: Any
    was_allowed: bool
    decision: Decision
    error: Optional[str] = None
    audit_hash: Optional[str] = None


class GovernedHFTool:
    """
    Hugging Face-compatible governed tool.

    Wraps any callable as a governed tool compatible with Hugging Face
    Transformers agents. All executions route through Shards-Kernel governance.

    Compatible with:
    - transformers.agents.Tool
    - transformers.agents.Agent
    - Hugging Face Hub tools

    Example:
        kernel = StrictKernel()
        kernel.boot(config)
        kernel.set_keyring({"key1": secret_key})

        # Create governed tool
        email_tool = GovernedHFTool(
            name="send_email",
            description="Send an email message",
            func=send_email_fn,
            kernel=kernel,
            inputs={"to": "string", "subject": "string", "body": "text"},
            output_type="string",
        )

        # Use with Hugging Face agent
        agent = Agent(tools=[email_tool], ...)

        # Or call directly with permit
        permit = create_permit(action="send_email", ...)
        result = email_tool(to="user@example.com", permit_token=permit)
    """

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable,
        kernel: BaseKernel,
        inputs: Optional[Dict[str, str]] = None,
        output_type: str = "any",
        actor: str = "hf-agent",
    ):
        """
        Initialize governed Hugging Face tool.

        Args:
            name: Tool name (must match permit action)
            description: Tool description for LLM
            func: Underlying function to execute
            kernel: Kernel instance for governance
            inputs: Input schema (e.g., {"query": "string", "max_results": "number"})
            output_type: Output type description
            actor: Actor identity for audit trail
        """
        self.name = name
        self.description = description
        self.func = func
        self.kernel = kernel
        self.inputs = inputs or {}
        self.output_type = output_type
        self.actor = actor
        self._call_count = 0

    def __call__(
        self,
        permit_token: Optional[PermitToken] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute tool through kernel governance (Hugging Face compatibility).

        Args:
            permit_token: Permit authorizing this execution
            **kwargs: Tool parameters

        Returns:
            Tool result

        Raises:
            PermitError: If permit required but missing/invalid
        """
        # Strip permit_token from kwargs before processing
        tool_kwargs = {k: v for k, v in kwargs.items() if k != "permit_token"}

        self._call_count += 1
        request_id = f"{self.name}-{self._call_count}-{uuid.uuid4().hex[:8]}"

        # Build kernel request
        request = KernelRequest(
            request_id=request_id,
            ts_ms=self.kernel.config.clock.now_ms(),
            actor=self.actor,
            intent=f"Execute {self.name}",
            tool_call=ToolCall(
                name=self.name,
                params=tool_kwargs,
            ),
            params=tool_kwargs,
        )

        # Submit through kernel
        receipt = self.kernel.submit(request, permit_token=permit_token)

        # Check decision
        if receipt.decision == Decision.ALLOW:
            return receipt.tool_result
        else:
            # Denied - raise error for Hugging Face agent
            raise PermitError(f"Tool {self.name} denied: {receipt.error}")

    def forward(self, *args, **kwargs) -> Any:
        """
        Hugging Face Tool.forward() compatibility.

        Called by Hugging Face agents during execution.
        """
        # Extract permit if provided
        permit_token = kwargs.pop("permit_token", None)
        return self(permit_token=permit_token, **kwargs)

    @property
    def inputs_schema(self) -> Dict[str, str]:
        """Return inputs schema (Hugging Face compatibility)."""
        return self.inputs

    @property
    def outputs(self) -> str:
        """Return output type (Hugging Face compatibility)."""
        return self.output_type


class HuggingFaceAdapter:
    """
    Adapter for integrating Shards-Kernel governance with Hugging Face agents.

    Provides utilities for wrapping Hugging Face tools and agents with
    permit-based governance and audit trails.

    Example:
        kernel = StrictKernel()
        kernel.boot(config)
        adapter = HuggingFaceAdapter(kernel, actor="my-hf-agent")

        # Wrap tools
        search_tool = adapter.wrap_tool(
            "web_search",
            search_fn,
            description="Search the web",
            inputs={"query": "string"},
        )

        email_tool = adapter.wrap_tool(
            "send_email",
            email_fn,
            description="Send email",
            inputs={"to": "string", "subject": "string", "body": "text"},
        )

        # Use with Hugging Face agent
        from transformers import Agent
        agent = Agent(tools=[search_tool, email_tool], ...)

        # Or call directly with permits
        permit = create_permit(action="send_email", ...)
        result = email_tool(to="user@example.com", permit_token=permit)

        # Export audit trail
        evidence = adapter.export_evidence()
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "hf-agent",
    ):
        """
        Initialize Hugging Face adapter.

        Args:
            kernel: Kernel instance for governance
            actor: Actor identity for audit trail
        """
        self.kernel = kernel
        self.actor = actor
        self._tools: Dict[str, GovernedHFTool] = {}

    def wrap_tool(
        self,
        name: str,
        func: Callable,
        description: str = "",
        inputs: Optional[Dict[str, str]] = None,
        output_type: str = "any",
    ) -> GovernedHFTool:
        """
        Wrap a callable as a governed Hugging Face tool.

        Args:
            name: Tool name (must match permit action)
            func: Function to wrap
            description: Tool description for LLM
            inputs: Input schema (e.g., {"query": "string"})
            output_type: Output type description

        Returns:
            GovernedHFTool instance compatible with HF agents
        """
        # Register tool in kernel's dispatcher
        self.kernel._dispatcher.registry.register(
            name=name,
            handler=func,
            description=description,
        )

        tool = GovernedHFTool(
            name=name,
            description=description,
            func=func,
            kernel=self.kernel,
            inputs=inputs,
            output_type=output_type,
            actor=self.actor,
        )

        self._tools[name] = tool
        return tool

    def wrap_hf_tool(self, hf_tool: Any) -> GovernedHFTool:
        """
        Wrap an existing Hugging Face Tool with governance.

        Args:
            hf_tool: Existing Hugging Face Tool instance

        Returns:
            GovernedHFTool wrapping the original tool
        """
        # Extract metadata from HF tool
        name = getattr(hf_tool, "name", "unknown_tool")
        description = getattr(hf_tool, "description", "")
        inputs = getattr(hf_tool, "inputs", {})
        output_type = getattr(hf_tool, "output_type", "any")

        # Wrap the tool's forward method
        return self.wrap_tool(
            name=name,
            func=hf_tool.forward if hasattr(hf_tool, "forward") else hf_tool,
            description=description,
            inputs=inputs,
            output_type=output_type,
        )

    def wrap_tools(self, tools: List[Any]) -> List[GovernedHFTool]:
        """
        Wrap multiple Hugging Face tools.

        Args:
            tools: List of HF Tool instances or callables

        Returns:
            List of governed tools
        """
        return [self.wrap_hf_tool(tool) for tool in tools]

    def get_tool(self, name: str) -> Optional[GovernedHFTool]:
        """
        Get a governed tool by name.

        Args:
            name: Tool name

        Returns:
            GovernedHFTool if found, None otherwise
        """
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        """List registered tool names."""
        return list(self._tools.keys())

    def export_evidence(self) -> Dict[str, Any]:
        """
        Export audit evidence from kernel.

        Returns:
            Evidence bundle as dict
        """
        from shards_kernel.common.codec import audit_entry_to_dict

        evidence = self.kernel.export_evidence()

        return {
            "kernel_id": evidence.kernel_id,
            "variant": evidence.variant,
            "root_hash": evidence.root_hash,
            "exported_at_ms": evidence.exported_at_ms,
            "entries": [audit_entry_to_dict(e) for e in evidence.ledger_entries],
            "entry_count": len(evidence.ledger_entries),
        }

    def halt(self) -> None:
        """Halt the kernel."""
        self.kernel.halt("operator halt")


class PermitInjector:
    """
    Helper for injecting permits into Hugging Face agent tool calls.

    Since Hugging Face agents don't natively support permit tokens,
    this class provides utilities to intercept and inject permits.

    Example:
        adapter = HuggingFaceAdapter(kernel)
        tools = [adapter.wrap_tool(...), adapter.wrap_tool(...)]

        injector = PermitInjector(adapter)

        # Set permits for specific actions
        injector.set_permit("send_email", email_permit)
        injector.set_permit("database_query", db_permit)

        # Tools will automatically use assigned permits
        agent = Agent(tools=tools, ...)
        result = agent.run("Send an email to the team")  # Uses email_permit
    """

    def __init__(self, adapter: HuggingFaceAdapter):
        """
        Initialize permit injector.

        Args:
            adapter: HuggingFaceAdapter instance
        """
        self.adapter = adapter
        self._permits: Dict[str, PermitToken] = {}

    def set_permit(self, tool_name: str, permit: PermitToken) -> None:
        """
        Assign permit to a specific tool.

        Args:
            tool_name: Name of tool
            permit: Permit token to use
        """
        self._permits[tool_name] = permit

    def get_permit(self, tool_name: str) -> Optional[PermitToken]:
        """
        Get assigned permit for a tool.

        Args:
            tool_name: Name of tool

        Returns:
            Permit if assigned, None otherwise
        """
        return self._permits.get(tool_name)

    def clear_permit(self, tool_name: str) -> None:
        """
        Remove permit assignment from tool.

        Args:
            tool_name: Name of tool
        """
        if tool_name in self._permits:
            del self._permits[tool_name]

    def clear_all_permits(self) -> None:
        """Clear all permit assignments."""
        self._permits.clear()


def create_huggingface_adapter(
    kernel_id: str = "hf-kernel",
    actor: str = "hf-agent",
    variant: str = "strict",
) -> HuggingFaceAdapter:
    """
    Create a Hugging Face adapter with a new kernel.

    Args:
        kernel_id: Kernel identifier
        actor: Actor name for tool calls
        variant: Kernel variant ("strict", "permissive", "evidence-first")

    Returns:
        Configured Hugging Face adapter
    """
    from shards_kernel.common.types import KernelConfig, VirtualClock

    if variant == "strict":
        kernel = StrictKernel()
    elif variant == "permissive":
        from shards_kernel.variants.permissive_kernel import PermissiveKernel

        kernel = PermissiveKernel()
    elif variant == "evidence-first":
        from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel

        kernel = EvidenceFirstKernel()
    else:
        raise ValueError(f"Unknown variant: {variant}")

    config = KernelConfig(
        kernel_id=kernel_id,
        variant=variant,
        clock=VirtualClock(),
    )
    kernel.boot(config)

    return HuggingFaceAdapter(kernel, actor)
