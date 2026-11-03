"""Execution dispatcher for Kernels.

The dispatcher handles tool invocation with explicit validation and
error handling. No implicit execution occurs.

When ``authorised_params`` is supplied, the tool is invoked with that object
and only if the live tool-call parameters are still identical to it. That is
the last check before a side effect.
"""

import copy
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from shards_kernel.common.types import ToolCall
from shards_kernel.common.errors import ToolError
from shards_kernel.common.codec import equal_json_values
from shards_kernel.execution.tools import Tool, ToolRegistry


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
    try:
        bound_params = copy.deepcopy(tool_params)
    except Exception as exc:
        return None, f"PARAM_BINDING_MISMATCH: parameters could not be bound ({exc})"
    if not equal_json_values(request_params, bound_params):
        return (
            None,
            "PARAM_BINDING_MISMATCH: request.params differ from tool_call.params",
        )
    return bound_params, None


def resolve_effective_params(
    handler: Any, params: dict[str, Any]
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Resolve inspectable handler defaults into explicit authorised kwargs.

    Handlers are trusted code. This binds their Python call arguments, not
    implicit behavior a handler might implement internally via **kwargs.
    """
    try:
        signature = inspect.signature(handler)
        # Do not authorise an invalid call or consume its permit budget.
        bound = signature.bind(**params)
        bound.apply_defaults()
        effective: dict[str, Any] = {}
        for parameter in signature.parameters.values():
            if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
                if parameter.name in bound.arguments:
                    return None, "PARAM_BINDING_MISMATCH: positional-only defaults cannot be authorised"
            elif parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                continue
            elif parameter.kind == inspect.Parameter.VAR_KEYWORD:
                effective.update(bound.arguments.get(parameter.name, {}))
            elif parameter.name in bound.arguments:
                effective[parameter.name] = bound.arguments[parameter.name]
        effective = copy.deepcopy(effective)
        if not equal_json_values(effective, effective):
            return None, "PARAM_BINDING_MISMATCH: effective parameters must be JSON values"
        return effective, None
    except (TypeError, ValueError, RecursionError) as exc:
        return None, f"PARAM_BINDING_MISMATCH: cannot bind tool arguments ({exc})"


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
        authorised_tool: Optional[Tool] = None,
        before_invoke: Optional[Callable[[], Optional[str]]] = None,
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

        bound_authorised_params = None
        if authorised_params is not None:
            try:
                bound_authorised_params = copy.deepcopy(authorised_params)
            except Exception as exc:
                return ExecutionResult(
                    success=False,
                    tool_name=name,
                    error=f"PARAM_BINDING_MISMATCH: parameters could not be bound ({exc})",
                )
        if bound_authorised_params is not None and not equal_json_values(params, bound_authorised_params):
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

        if bound_authorised_params is not None:
            params = bound_authorised_params

        # Execute
        try:
            if before_invoke is not None:
                denial = before_invoke()
                if denial:
                    return ExecutionResult(success=False, tool_name=name, error=denial)
            if authorised_tool is None:
                result = self._registry.invoke(name, params)
            else:
                result = self._registry.invoke(name, params, expected_tool=authorised_tool)
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
