"""Tool registry and built-in tools for Kernels.

Tools are deterministic functions that can be invoked through the kernel.
All tools must be explicitly registered; no dynamic discovery is allowed.
"""

from dataclasses import dataclass
from typing import Any, Callable, Optional

from shards_kernel.common.errors import ToolError


@dataclass(frozen=True)
class Tool:
    """Definition of a registered tool."""

    name: str
    description: str
    handler: Callable[..., Any]
    param_schema: dict[str, type]


class ToolRegistry:
    """Registry of available tools.

    Tools must be explicitly registered. The registry does not perform
    dynamic discovery or import-by-name.
    """

    def __init__(self) -> None:
        """Initialize an empty tool registry."""
        self._tools: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str = "",
        param_schema: Optional[dict[str, type]] = None,
    ) -> None:
        """Register a tool.

        Args:
            name: Unique tool name.
            handler: Function to invoke for this tool.
            description: Human-readable description.
            param_schema: Dictionary mapping parameter names to types.

        Raises:
            ToolError: If tool name is already registered.
        """
        if name in self._tools:
            raise ToolError(f"Tool '{name}' is already registered")

        self._tools[name] = Tool(
            name=name,
            description=description,
            handler=handler,
            param_schema=param_schema or {},
        )

    def unregister(self, name: str) -> None:
        """Unregister a tool.

        Args:
            name: Tool name to unregister.

        Raises:
            ToolError: If tool is not registered.
        """
        if name not in self._tools:
            raise ToolError(f"Tool '{name}' is not registered")
        del self._tools[name]

    def get(self, name: str) -> Optional[Tool]:
        """Get a tool by name.

        Args:
            name: Tool name.

        Returns:
            Tool if found, None otherwise.
        """
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        """Check if a tool is registered.

        Args:
            name: Tool name.

        Returns:
            True if registered, False otherwise.
        """
        return name in self._tools

    def list_tools(self) -> list[str]:
        """List all registered tool names.

        Returns:
            List of tool names.
        """
        return list(self._tools.keys())

    def invoke(self, name: str, params: dict[str, Any]) -> Any:
        """Invoke a tool with parameters.

        Args:
            name: Tool name.
            params: Parameters to pass to the tool.

        Returns:
            Tool execution result.

        Raises:
            ToolError: If tool not found or execution fails.
        """
        tool = self.get(name)
        if tool is None:
            raise ToolError(f"Tool '{name}' not found")

        try:
            return tool.handler(**params)
        except TypeError as e:
            raise ToolError(f"Invalid parameters for tool '{name}': {e}")
        except Exception as e:
            raise ToolError(f"Tool '{name}' execution failed: {e}")


def create_default_registry() -> ToolRegistry:
    """Create a registry with built-in tools.

    Returns:
        ToolRegistry with echo and add tools registered.
    """
    registry = ToolRegistry()

    # Built-in: echo
    def echo(text: str) -> str:
        """Return the input text unchanged."""
        return text

    registry.register(
        name="echo",
        handler=echo,
        description="Return the input text unchanged",
        param_schema={"text": str},
    )

    # Built-in: add
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    registry.register(
        name="add",
        handler=add,
        description="Add two integers",
        param_schema={"a": int, "b": int},
    )

    return registry
