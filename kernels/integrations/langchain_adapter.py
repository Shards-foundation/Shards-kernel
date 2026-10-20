"""
KERNELS LangChain Integration

Adapter for LangChain tool integration with permit-based governance.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, Union

from kernels.common.types import KernelRequest, ToolCall, Decision
from kernels.variants.base import BaseKernel
from kernels.variants.strict_kernel import StrictKernel
from kernels.permits import PermitToken
from kernels.common.errors import PermitError


@dataclass
class LangChainToolResult:
    """Result from a governed LangChain tool execution."""

    tool_name: str
    result: Any
    was_allowed: bool
    decision: Decision
    error: Optional[str] = None
    audit_hash: Optional[str] = None


class GovernedTool:
    """
    LangChain-compatible tool wrapper with KERNELS governance.

    Wraps any callable as a governed tool that routes through a kernel.
    All executions require permit tokens when kernel has keyring configured.

    Example:
        kernel = StrictKernel()
        kernel.boot(config)
        kernel.set_keyring({"key1": secret_key})

        def send_email(to: str, subject: str, body: str) -> str:
            # ... actual email sending
            return f"Sent to {to}"

        # Wrap dangerous tool with governance
        governed_email = GovernedTool(
            name="send_email",
            func=send_email,
            kernel=kernel,
            actor="langchain-agent",
            description="Send an email",
        )

        # Execution requires permit
        permit = create_permit(action="send_email", ...)
        result = governed_email.run(
            permit_token=permit,
            to="user@example.com",
            subject="Test",
            body="Hello"
        )
    """

    def __init__(
        self,
        name: str,
        func: Callable,
        kernel: BaseKernel,
        actor: str = "langchain-agent",
        description: str = "",
        require_permit: bool = True,
    ):
        """
        Initialize governed tool.

        Args:
            name: Tool name (must match permit action)
            func: Underlying function to execute
            kernel: Kernel instance for governance
            actor: Actor identity for audit trail
            description: Tool description
            require_permit: If True, always require permit (even without keyring)
        """
        self.name = name
        self.func = func
        self.kernel = kernel
        self.actor = actor
        self.description = description
        self.require_permit = require_permit
        self._call_count = 0

    def run(
        self,
        permit_token: Optional[PermitToken] = None,
        intent: Optional[str] = None,
        **kwargs: Any,
    ) -> LangChainToolResult:
        """
        Execute tool through kernel governance.

        Args:
            permit_token: Permit authorizing this execution
            intent: Human-readable intent
            **kwargs: Tool parameters

        Returns:
            LangChainToolResult with execution outcome

        Raises:
            PermitError: If permit required but missing/invalid
        """
        self._call_count += 1
        request_id = f"{self.name}-{self._call_count}-{uuid.uuid4().hex[:8]}"

        # Build kernel request
        request = KernelRequest(
            request_id=request_id,
            ts_ms=self.kernel.config.clock.now_ms(),
            actor=self.actor,
            intent=intent or f"Execute {self.name}",
            tool_call=ToolCall(
                name=self.name,
                params=kwargs,
            ),
            params=kwargs,
        )

        # Submit through kernel
        receipt = self.kernel.submit(request, permit_token=permit_token)

        # Extract audit hash
        evidence = self.kernel.export_evidence()
        audit_hash = (
            evidence.ledger_entries[-1].entry_hash if evidence.ledger_entries else None
        )

        # Build result
        if receipt.decision == Decision.ALLOW:
            return LangChainToolResult(
                tool_name=self.name,
                result=receipt.tool_result,
                was_allowed=True,
                decision=receipt.decision,
                audit_hash=audit_hash,
            )
        else:
            # Denied
            return LangChainToolResult(
                tool_name=self.name,
                result=None,
                was_allowed=False,
                decision=receipt.decision,
                error=receipt.error,
                audit_hash=audit_hash,
            )

    def invoke(
        self,
        input: Union[str, Dict[str, Any]],
        permit_token: Optional[PermitToken] = None,
    ) -> Any:
        """
        LangChain Tool.invoke() compatibility.

        Args:
            input: Tool input (string or dict)
            permit_token: Optional permit token

        Returns:
            Tool result or raises PermitError
        """
        # Convert string input to dict if needed
        if isinstance(input, str):
            params = {"input": input}
        else:
            params = input

        result = self.run(permit_token=permit_token, **params)

        if not result.was_allowed:
            raise PermitError(f"Tool {self.name} denied: {result.error}")

        return result.result

    def __call__(
        self, *args, permit_token: Optional[PermitToken] = None, **kwargs
    ) -> Any:
        """Direct call syntax."""
        result = self.run(permit_token=permit_token, **kwargs)

        if not result.was_allowed:
            raise PermitError(f"Tool {self.name} denied: {result.error}")

        return result.result


class LangChainAdapter:
    """
    Adapter for integrating KERNELS governance with LangChain.

    Provides utilities for wrapping LangChain tools, agents, and chains
    with permit-based governance and audit trails.

    Example:
        kernel = StrictKernel()
        kernel.boot(config)
        adapter = LangChainAdapter(kernel, actor="my-agent")

        # Wrap existing tools
        governed_tools = [
            adapter.wrap_tool("search", search_fn),
            adapter.wrap_tool("calculator", calc_fn),
            adapter.wrap_tool("send_email", email_fn),  # Dangerous tool
        ]

        # Use with LangChain agent
        agent = create_react_agent(llm, governed_tools, prompt)

        # Execute with permits
        permit = create_permit(action="send_email", ...)
        adapter.set_permit(permit)
        result = agent.invoke({"input": "Send summary to team"})

        # Export audit trail
        evidence = adapter.export_evidence()
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "langchain-agent",
    ):
        """
        Initialize LangChain adapter.

        Args:
            kernel: Kernel instance for governance
            actor: Actor identity for audit trail
        """
        self.kernel = kernel
        self.actor = actor
        self._current_permit: Optional[PermitToken] = None
        self._tools: Dict[str, GovernedTool] = {}

    def wrap_tool(
        self,
        name: str,
        func: Callable,
        description: str = "",
        require_permit: bool = True,
    ) -> GovernedTool:
        """
        Wrap a callable as a governed tool.

        Args:
            name: Tool name (must match permit action)
            func: Function to wrap
            description: Tool description
            require_permit: Whether permit is always required

        Returns:
            GovernedTool instance
        """
        # Register tool in kernel's dispatcher
        self.kernel._dispatcher.registry.register(
            name=name,
            handler=func,
            description=description,
        )

        tool = GovernedTool(
            name=name,
            func=func,
            kernel=self.kernel,
            actor=self.actor,
            description=description,
            require_permit=require_permit,
        )
        self._tools[name] = tool
        return tool

    def set_permit(self, permit: PermitToken) -> None:
        """
        Set current permit for subsequent tool calls.

        Args:
            permit: Permit token to use
        """
        self._current_permit = permit

    def clear_permit(self) -> None:
        """Clear current permit."""
        self._current_permit = None

    def get_tool(self, name: str) -> Optional[GovernedTool]:
        """
        Get a governed tool by name.

        Args:
            name: Tool name

        Returns:
            GovernedTool if found, None otherwise
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
        from kernels.common.codec import audit_entry_to_dict

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


def create_langchain_adapter(
    kernel_id: str = "langchain-kernel",
    actor: str = "langchain-agent",
    variant: str = "strict",
) -> LangChainAdapter:
    """
    Create a LangChain adapter with a new kernel.

    Args:
        kernel_id: Kernel identifier
        actor: Actor name for tool calls
        variant: Kernel variant ("strict", "permissive", "evidence-first")

    Returns:
        Configured LangChain adapter
    """
    from kernels.common.types import KernelConfig, VirtualClock

    if variant == "strict":
        kernel = StrictKernel()
    elif variant == "permissive":
        from kernels.variants.permissive_kernel import PermissiveKernel

        kernel = PermissiveKernel()
    elif variant == "evidence-first":
        from kernels.variants.evidence_first_kernel import EvidenceFirstKernel

        kernel = EvidenceFirstKernel()
    else:
        raise ValueError(f"Unknown variant: {variant}")

    config = KernelConfig(
        kernel_id=kernel_id,
        variant=variant,
        clock=VirtualClock(),
    )
    kernel.boot(config)

    return LangChainAdapter(kernel, actor)
