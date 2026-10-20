"""
KERNELS Async Dispatcher

Provides async tool execution capabilities.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass

from kernels.common.types import ToolCall


@dataclass
class AsyncToolResult:
    """Result from async tool execution."""

    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: int = 0


class AsyncToolRegistry:
    """
    Registry for async tools.

    Supports both sync and async tool functions.
    """

    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        name: str,
        description: str = "",
        params_schema: Optional[Dict] = None,
    ) -> Callable:
        """
        Decorator to register a tool.

        Args:
            name: Tool name
            description: Tool description
            params_schema: JSON schema for parameters

        Returns:
            Decorator function
        """

        def decorator(fn: Callable) -> Callable:
            self._tools[name] = fn
            self._metadata[name] = {
                "name": name,
                "description": description,
                "params_schema": params_schema or {},
                "is_async": asyncio.iscoroutinefunction(fn),
            }
            return fn

        return decorator

    def register_tool(
        self,
        name: str,
        fn: Callable,
        description: str = "",
        params_schema: Optional[Dict] = None,
    ) -> None:
        """
        Register a tool directly.

        Args:
            name: Tool name
            fn: Tool function
            description: Tool description
            params_schema: JSON schema for parameters
        """
        self._tools[name] = fn
        self._metadata[name] = {
            "name": name,
            "description": description,
            "params_schema": params_schema or {},
            "is_async": asyncio.iscoroutinefunction(fn),
        }

    def get(self, name: str) -> Optional[Callable]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """Get tool metadata."""
        return self._metadata.get(name)

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools


class AsyncDispatcher:
    """
    Registry holder for async tool callables.

    ``dispatch`` does not run those callables. Authorised execution goes
    through ``AsyncKernel.submit`` and a permit bound to the call.
    """

    def __init__(
        self,
        registry: AsyncToolRegistry,
        default_timeout: float = 30.0,
    ):
        self.registry = registry
        self.default_timeout = default_timeout

    async def dispatch(
        self,
        tool_call: ToolCall,
        timeout: Optional[float] = None,
    ) -> AsyncToolResult:
        """
        Refuse to run a tool.

        This registry is not an authorisation path. Running a tool here
        would skip permit binding, the intent record, and halt-on-fault.
        Submit the call through ``AsyncKernel`` with a permit bound to the
        parameters that should run.
        """
        del tool_call, timeout
        return AsyncToolResult(
            success=False,
            error=(
                "MISSING_PERMIT: AsyncDispatcher does not execute tools. "
                "Submit the call through AsyncKernel with a permit bound "
                "to the parameters."
            ),
        )

    async def dispatch_batch(
        self,
        tool_calls: list[ToolCall],
        concurrency: int = 10,
        timeout: Optional[float] = None,
    ) -> list[AsyncToolResult]:
        """
        Dispatch multiple tool calls with controlled concurrency.

        Args:
            tool_calls: List of tool calls to execute
            concurrency: Maximum concurrent executions
            timeout: Timeout per tool call

        Returns:
            List of results in same order as tool_calls
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def dispatch_with_semaphore(tc: ToolCall) -> AsyncToolResult:
            async with semaphore:
                return await self.dispatch(tc, timeout)

        tasks = [dispatch_with_semaphore(tc) for tc in tool_calls]
        return await asyncio.gather(*tasks)


# Example async tools


async def async_echo(params: Dict[str, Any]) -> Dict[str, Any]:
    """Async echo tool for testing."""
    await asyncio.sleep(0.01)  # Simulate async work
    return {"echoed": params.get("message", "")}


async def async_delay(params: Dict[str, Any]) -> Dict[str, Any]:
    """Async delay tool for testing."""
    delay = params.get("seconds", 1.0)
    await asyncio.sleep(delay)
    return {"delayed": delay}


async def async_fetch(params: Dict[str, Any]) -> Dict[str, Any]:
    """Async fetch tool (mock implementation)."""
    url = params.get("url", "")
    # In real implementation, use aiohttp
    await asyncio.sleep(0.1)  # Simulate network delay
    return {"url": url, "status": 200, "body": "mock response"}


def create_default_async_registry() -> AsyncToolRegistry:
    """Create a registry with default async tools."""
    registry = AsyncToolRegistry()

    registry.register_tool(
        "echo",
        async_echo,
        description="Echo a message",
        params_schema={"message": {"type": "string"}},
    )

    registry.register_tool(
        "delay",
        async_delay,
        description="Delay for specified seconds",
        params_schema={"seconds": {"type": "number"}},
    )

    registry.register_tool(
        "fetch",
        async_fetch,
        description="Fetch a URL",
        params_schema={"url": {"type": "string"}},
    )

    return registry
