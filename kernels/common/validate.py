"""Validation utilities for Kernels.

Provides request validation and ambiguity detection functions.
"""

from typing import Any, Union

from kernels.common.types import KernelRequest, ToolCall
from kernels.common.codec import serialize_deterministic


def validate_request(request: KernelRequest) -> list[str]:
    """Validate a kernel request structure.

    Checks that all required fields are present and correctly typed.

    Args:
        request: The request to validate.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors: list[str] = []

    if not request.request_id:
        errors.append("request_id is required")
    elif not isinstance(request.request_id, str):
        errors.append("request_id must be a string")

    if request.ts_ms is None:
        errors.append("ts_ms is required")
    elif not isinstance(request.ts_ms, int):
        errors.append("ts_ms must be an integer")
    elif request.ts_ms < 0:
        errors.append("ts_ms must be non-negative")

    if not request.actor:
        errors.append("actor is required")
    elif not isinstance(request.actor, str):
        errors.append("actor must be a string")

    if request.intent is None:
        errors.append("intent is required")
    elif not isinstance(request.intent, str):
        errors.append("intent must be a string")

    if request.params is not None and not isinstance(request.params, dict):
        errors.append("params must be a dictionary")

    if request.tool_call is not None:
        tool_errors = validate_tool_call(request.tool_call)
        errors.extend(tool_errors)

    return errors


def validate_tool_call(tool_call: Union[ToolCall, dict[str, Any]]) -> list[str]:
    """Validate a tool call structure.

    Args:
        tool_call: The tool call to validate.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors: list[str] = []

    if isinstance(tool_call, dict):
        if "name" not in tool_call:
            errors.append("tool_call.name is required")
        elif not isinstance(tool_call.get("name"), str):
            errors.append("tool_call.name must be a string")
        elif not tool_call.get("name"):
            errors.append("tool_call.name cannot be empty")

        if "params" in tool_call and not isinstance(tool_call.get("params"), dict):
            errors.append("tool_call.params must be a dictionary")
    elif isinstance(tool_call, ToolCall):
        if not tool_call.name:
            errors.append("tool_call.name is required")
        elif not isinstance(tool_call.name, str):
            errors.append("tool_call.name must be a string")
    else:
        errors.append("tool_call has invalid structure")

    return errors


def check_ambiguity(
    request: KernelRequest,
    max_intent_length: int = 4096,
    strict: bool = True,
) -> list[str]:
    """Check request for ambiguity indicators.

    Ambiguity heuristics detect requests that cannot be unambiguously
    interpreted. In strict mode, more conditions trigger ambiguity.

    Args:
        request: The request to check.
        max_intent_length: Maximum allowed intent length.
        strict: Whether to use strict ambiguity checking.

    Returns:
        List of ambiguity error messages. Empty if unambiguous.
    """
    errors: list[str] = []

    # Empty intent is always ambiguous
    if not request.intent or request.intent.strip() == "":
        errors.append("Empty intent is ambiguous")

    # Overly long intent is ambiguous
    if request.intent and len(request.intent) > max_intent_length:
        errors.append(f"Intent exceeds maximum length of {max_intent_length}")

    # In strict mode, tool_call with empty name is ambiguous
    if strict and request.tool_call is not None:
        if isinstance(request.tool_call, dict):
            if not request.tool_call.get("name"):
                errors.append("Tool call with empty name is ambiguous")
        elif isinstance(request.tool_call, ToolCall):
            if not request.tool_call.name:
                errors.append("Tool call with empty name is ambiguous")
        else:
            errors.append("Tool call with invalid structure is ambiguous")

    # Params not being a dict is ambiguous
    if request.params is not None and not isinstance(request.params, dict):
        errors.append("Params must be a dictionary")

    return errors


def check_param_size(
    params: dict[str, Any],
    max_bytes: int = 65536,
) -> bool:
    """Check if serialized params exceed maximum size.

    Args:
        params: Parameters dictionary to check.
        max_bytes: Maximum allowed size in bytes.

    Returns:
        True if within limits, False if exceeds.
    """
    serialized = serialize_deterministic(params)
    return len(serialized.encode("utf-8")) <= max_bytes
