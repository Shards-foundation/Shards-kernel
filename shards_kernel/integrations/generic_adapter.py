"""
Shards-Kernel Generic Integration Adapter

Universal adapter for integrating Shards-Kernel with any tool-calling framework.

This adapter provides a flexible pattern for wrapping tools from:
- OpenClaw/Moltbook
- Custom agent frameworks
- Any tool-calling system

Usage:
    adapter = GenericAdapter(kernel)

    # Wrap a tool with custom interface
    def my_tool_wrapper(permit_token=None, **kwargs):
        return adapter.call_tool("my_tool", kwargs, permit_token)

    # Or use the decorator pattern
    @adapter.govern("my_tool")
    def my_tool(param1: str, param2: int):
        return f"Executed with {param1}, {param2}"
"""

from __future__ import annotations

import uuid
import functools
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable

from shards_kernel.common.types import KernelRequest, ToolCall, Decision
from shards_kernel.variants.base import BaseKernel
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.permits import PermitToken
from shards_kernel.common.errors import PermitError


@dataclass
class ToolExecutionResult:
    """Generic result from governed tool execution."""

    tool_name: str
    result: Any
    was_allowed: bool
    decision: Decision
    request_id: str
    error: Optional[str] = None
    audit_hash: Optional[str] = None
    permit_digest: Optional[str] = None


class GenericAdapter:
    """
    Universal adapter for any tool-calling framework.

    This adapter provides a flexible interface for wrapping tools from
    any framework with Shards-Kernel governance.

    Examples:

    1. Simple function wrapping:
        adapter = GenericAdapter(kernel)

        result = adapter.call_tool(
            tool_name="send_email",
            params={"to": "user@example.com", "subject": "Test"},
            permit_token=permit,
        )

    2. Decorator pattern:
        @adapter.govern("send_email")
        def send_email(to: str, subject: str, body: str):
            # ... actual email sending
            return f"Email sent to {to}"

        # Now function requires permit
        result = send_email(to="user@example.com", permit_token=permit)

    3. Wrapper factory:
        def create_governed_tool(name, func):
            return adapter.create_wrapper(name, func)

        governed_email = create_governed_tool("send_email", send_email_fn)

    4. Framework-specific adapter:
        class MyFrameworkAdapter:
            def __init__(self, kernel):
                self.generic = GenericAdapter(kernel)

            def wrap_tool(self, name, func):
                # Adapt to MyFramework's interface
                return MyFrameworkTool(
                    name=name,
                    execute=lambda **kw: self.generic.call_tool(name, kw, kw.pop('permit_token', None))
                )
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "generic-agent",
        auto_register: bool = True,
    ):
        """
        Initialize generic adapter.

        Args:
            kernel: Kernel instance for governance
            actor: Default actor identity for audit trail
            auto_register: Automatically register tools in kernel dispatcher
        """
        self.kernel = kernel
        self.actor = actor
        self.auto_register = auto_register
        self._tools: Dict[str, Callable] = {}
        self._call_count = 0

    def call_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        permit_token: Optional[PermitToken] = None,
        actor: Optional[str] = None,
        intent: Optional[str] = None,
    ) -> ToolExecutionResult:
        """
        Execute a tool through kernel governance.

        Args:
            tool_name: Name of tool to execute
            params: Tool parameters
            permit_token: Permit authorizing execution
            actor: Override actor identity (uses default if None)
            intent: Human-readable intent

        Returns:
            ToolExecutionResult with execution outcome
        """
        self._call_count += 1
        request_id = f"{tool_name}-{self._call_count}-{uuid.uuid4().hex[:8]}"

        # Build kernel request
        request = KernelRequest(
            request_id=request_id,
            ts_ms=self.kernel.config.clock.now_ms(),
            actor=actor or self.actor,
            intent=intent or f"Execute {tool_name}",
            tool_call=ToolCall(
                name=tool_name,
                params=params,
            ),
            params=params,
        )

        # Submit through kernel
        receipt = self.kernel.submit(request, permit_token=permit_token)

        # Extract audit info
        evidence = self.kernel.export_evidence()
        latest_entry = evidence.ledger_entries[-1] if evidence.ledger_entries else None
        audit_hash = latest_entry.entry_hash if latest_entry else None
        permit_digest = latest_entry.permit_digest if latest_entry else None

        # Build result
        return ToolExecutionResult(
            tool_name=tool_name,
            result=receipt.tool_result if receipt.decision == Decision.ALLOW else None,
            was_allowed=(receipt.decision == Decision.ALLOW),
            decision=receipt.decision,
            request_id=request_id,
            error=receipt.error if receipt.decision != Decision.ALLOW else None,
            audit_hash=audit_hash,
            permit_digest=permit_digest,
        )

    def register_tool(
        self,
        name: str,
        func: Callable,
        description: str = "",
    ) -> None:
        """
        Register a tool for governance.

        Args:
            name: Tool name
            func: Tool function
            description: Tool description
        """
        self._tools[name] = func

        if self.auto_register:
            # Register in kernel's dispatcher
            self.kernel._dispatcher.registry.register(
                name=name,
                handler=func,
                description=description,
            )

    def create_wrapper(
        self,
        name: str,
        func: Callable,
        description: str = "",
        raise_on_deny: bool = True,
    ) -> Callable:
        """
        Create a governed wrapper around a function.

        Args:
            name: Tool name
            func: Function to wrap
            description: Tool description
            raise_on_deny: If True, raise PermitError on denial

        Returns:
            Wrapped function that requires permit
        """
        self.register_tool(name, func, description)

        @functools.wraps(func)
        def wrapper(permit_token: Optional[PermitToken] = None, **kwargs):
            result = self.call_tool(name, kwargs, permit_token)

            if not result.was_allowed:
                if raise_on_deny:
                    raise PermitError(f"Tool {name} denied: {result.error}")
                return None

            return result.result

        return wrapper

    def govern(
        self,
        name: str,
        description: str = "",
        raise_on_deny: bool = True,
    ) -> Callable:
        """
        Decorator for governing a function.

        Args:
            name: Tool name
            description: Tool description
            raise_on_deny: If True, raise PermitError on denial

        Returns:
            Decorator function

        Example:
            @adapter.govern("send_email", description="Send email message")
            def send_email(to: str, subject: str, body: str):
                # ... implementation
                return "Email sent"

            # Function now requires permit
            send_email(to="user@example.com", permit_token=permit)
        """

        def decorator(func: Callable) -> Callable:
            return self.create_wrapper(name, func, description, raise_on_deny)

        return decorator

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


def create_generic_adapter(
    kernel_id: str = "generic-kernel",
    actor: str = "generic-agent",
    variant: str = "strict",
    auto_register: bool = True,
) -> GenericAdapter:
    """
    Create a generic adapter with a new kernel.

    Args:
        kernel_id: Kernel identifier
        actor: Actor name for tool calls
        variant: Kernel variant ("strict", "permissive", "evidence-first")
        auto_register: Automatically register tools in dispatcher

    Returns:
        Configured generic adapter
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

    return GenericAdapter(kernel, actor, auto_register)


# ============================================================================
# Example Framework-Specific Adapters
# ============================================================================


class MoltbookAdapter(GenericAdapter):
    """
    Adapter for Moltbook/OpenClaw frameworks.

    Moltbook is a tool-calling framework. This adapter shows how to
    integrate Shards-Kernel governance.

    Usage:
        adapter = MoltbookAdapter(kernel)

        # If Moltbook uses a specific tool interface:
        tool = adapter.wrap_moltbook_tool(moltbook_tool_instance)

        # Or create tools directly:
        @adapter.govern("my_tool")
        def my_tool(param1: str):
            return f"Result: {param1}"
    """

    def wrap_moltbook_tool(self, tool: Any, name: Optional[str] = None) -> Callable:
        """
        Wrap a Moltbook/OpenClaw tool with governance.

        Args:
            tool: Moltbook tool instance
            name: Override tool name (extracted from tool if None)

        Returns:
            Governed wrapper for the tool
        """
        # Extract tool metadata (adapt to actual Moltbook interface)
        tool_name = name or getattr(tool, "name", "unknown")
        description = getattr(tool, "description", "")

        # Get the callable (adapt to actual Moltbook interface)
        if callable(tool):
            func = tool
        elif hasattr(tool, "execute"):
            func = tool.execute
        elif hasattr(tool, "__call__"):
            func = tool.__call__
        else:
            raise ValueError(f"Tool {tool_name} is not callable")

        return self.create_wrapper(tool_name, func, description)


def create_moltbook_adapter(
    kernel_id: str = "moltbook-kernel",
    actor: str = "moltbook-agent",
) -> MoltbookAdapter:
    """
    Create a Moltbook/OpenClaw adapter with a new kernel.

    Args:
        kernel_id: Kernel identifier
        actor: Actor name for tool calls

    Returns:
        Configured Moltbook adapter
    """
    from shards_kernel.common.types import KernelConfig, VirtualClock

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id=kernel_id,
        variant="strict",
        clock=VirtualClock(),
    )
    kernel.boot(config)

    return MoltbookAdapter(kernel, actor)
