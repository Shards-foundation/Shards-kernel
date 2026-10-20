"""Execution dispatcher for Kernels.

The dispatcher handles tool invocation with explicit validation and
error handling. No implicit execution occurs.

When ``authorised_params`` is supplied, the tool is invoked with that object
and only if the live tool-call parameters are still identical to it. That is
the last check before a side effect.
"""

import copy
from dataclasses import dataclass
from typing import Any, Optional, Union

from kernels.common.types import ToolCall
from kernels.common.errors import ToolError
from kernels.execution.tools import ToolRegistry


@dataclass
class ExecutionResult:
    """Result of a tool execution."""

    success: bool
    tool_name: str
    result: Optional[Any] = None
    error: Optional[str] = None


def resolve_bound_params(
    request_params: Any,
    tool_params: Any,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Return one canonical parameter object, or an error if the two differ.

    The returned dictionary is a deep copy. Callers must authorise, execute,
    and audit that copy so a later mutation of either input cannot change
    what was permitted.

    Args:
        request_params: Parameters on the kernel request.
        tool_params: Parameters on the tool call.

    Returns:
        ``(bound_params, None)`` when the two mappings are equal, or
        ``(None, error)`` when they are not a single authorisable object.
    """
    if not isinstance(request_params, dict) or not isinstance(tool_params, dict):
        return None, "PARAM_BINDING_MISMATCH: parameters must be dictionaries"
    if request_params != tool_params:
        return (
            None,
            "PARAM_BINDING_MISMATCH: request.params differ from tool_call.params",
        )
    try:
        return copy.deepcopy(tool_params), None
    except Exception as exc:
        return None, f"PARAM_BINDING_MISMATCH: parameters could not be bound ({exc})"


class Dispatcher:
    """Dispatcher for tool execution.

    The dispatcher validates tool calls and invokes tools through
    the registry. All execution is explicit and synchronous.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        """Initialize dispatcher with a tool registry.

        Args:
            registry: Tool registry to use for lookups.
        """
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        """Return the tool registry."""
        return self._registry

    def validate_tool_call(
        self, tool_call: Union[ToolCall, dict[str, Any]]
    ) -> list[str]:
        """Validate a tool call before execution.

        Args:
            tool_call: Tool call to validate.

        Returns:
            List of validation errors. Empty if valid.
        """
        errors: list[str] = []

        # Extract name
        if isinstance(tool_call, ToolCall):
            name = tool_call.name
            params = tool_call.params
        elif isinstance(tool_call, dict):
            name = tool_call.get("name", "")
            params = tool_call.get("params", {})
        else:
            return ["Invalid tool call structure"]

        # Check name
        if not name:
            errors.append("Tool name is required")
            return errors

        # Check tool exists
        if not self._registry.has(name):
            errors.append(f"Tool '{name}' is not registered")
            return errors

        # Check params is dict
        if not isinstance(params, dict):
            errors.append("Tool params must be a dictionary")

        return errors

    def execute(
        self,
        tool_call: Union[ToolCall, dict[str, Any]],
        authorised_params: Optional[dict[str, Any]] = None,
        authorised_tool_name: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a tool call.

        Args:
            tool_call: Tool call to execute.
            authorised_params: Parameters the permit (or the insecure opt-out)
                bound. When set, execution uses a copy of this object and
                refuses if the live tool-call parameters differ.
            authorised_tool_name: Tool name that was authorised. When set, a
                different live name is refused.

        Returns:
            ExecutionResult with success status and result or error.
        """
        # Extract name and params
        if isinstance(tool_call, ToolCall):
            name = tool_call.name
            raw_params = tool_call.params
        elif isinstance(tool_call, dict):
            name = tool_call.get("name", "")
            raw_params = tool_call.get("params", {})
        else:
            return ExecutionResult(
                success=False,
                tool_name="",
                error="Invalid tool call structure",
            )

        if not isinstance(raw_params, dict):
            return ExecutionResult(
                success=False,
                tool_name=name,
                error="Tool params must be a dictionary",
            )
        params = dict(raw_params)

        if authorised_tool_name is not None and name != authorised_tool_name:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=(
                    "PARAM_BINDING_MISMATCH: "
                    f"tool '{name}' is not the authorised tool '{authorised_tool_name}'"
                ),
            )

        if authorised_params is not None and params != authorised_params:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=(
                    "PARAM_BINDING_MISMATCH: tool_call.params differ "
                    "from the authorised parameters"
                ),
            )

        # Validate
        errors = self.validate_tool_call(tool_call)
        if errors:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error="; ".join(errors),
            )

        if authorised_params is not None:
            try:
                params = copy.deepcopy(authorised_params)
            except Exception as exc:
                return ExecutionResult(
                    success=False,
                    tool_name=name,
                    error=f"PARAM_BINDING_MISMATCH: parameters could not be bound ({exc})",
                )

        # Execute
        try:
            result = self._registry.invoke(name, params)
            return ExecutionResult(
                success=True,
                tool_name=name,
                result=result,
            )
        except ToolError as e:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=str(e),
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=f"Unexpected error: {e}",
            )

    def list_available_tools(self) -> list[str]:
        """List all available tools.

        Returns:
            List of tool names.
        """
        return self._registry.list_tools()
