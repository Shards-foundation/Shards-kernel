"""Composable jurisdiction rule functions.

Each rule function checks a specific aspect of jurisdiction compliance.
Rules return error messages if violated, or an empty list if passed.
"""

from dataclasses import dataclass

from shards_kernel.common.types import KernelRequest, ToolCall
from shards_kernel.common.codec import serialize_deterministic
from shards_kernel.jurisdiction.policy import JurisdictionPolicy


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    allowed: bool
    violations: list[str]


def check_actor_allowed(
    request: KernelRequest, policy: JurisdictionPolicy
) -> list[str]:
    """Check if the request actor is allowed by policy.

    Args:
        request: The request to check.
        policy: The policy to evaluate against.

    Returns:
        List of violation messages. Empty if allowed.
    """
    if not policy.allows_actor(request.actor):
        return [f"Actor '{request.actor}' is not in allowed actors"]
    return []


def check_tool_allowed(request: KernelRequest, policy: JurisdictionPolicy) -> list[str]:
    """Check if the request tool is allowed by policy.

    Args:
        request: The request to check.
        policy: The policy to evaluate against.

    Returns:
        List of violation messages. Empty if allowed.
    """
    if request.tool_call is None:
        if policy.allow_intent_only:
            return []
        # No tool call is not a violation if allow_intent_only
        return []

    tool_name = (
        request.tool_call.name
        if isinstance(request.tool_call, ToolCall)
        else request.tool_call.get("name", "")
    )

    if not policy.allows_tool(tool_name):
        return [f"Tool '{tool_name}' is not in allowed tools"]
    return []


def check_required_fields(
    request: KernelRequest, policy: JurisdictionPolicy
) -> list[str]:
    """Check if all required fields are present in the request.

    Args:
        request: The request to check.
        policy: The policy to evaluate against.

    Returns:
        List of violation messages. Empty if all fields present.
    """
    violations = []

    field_map = {
        "request_id": request.request_id,
        "actor": request.actor,
        "intent": request.intent,
        "ts_ms": request.ts_ms,
    }

    for field in policy.required_fields:
        value = field_map.get(field)
        if value is None or (isinstance(value, str) and not value):
            violations.append(f"Required field '{field}' is missing or empty")

    return violations


def check_param_size(request: KernelRequest, policy: JurisdictionPolicy) -> list[str]:
    """Check if request parameters are within size limits.

    Args:
        request: The request to check.
        policy: The policy to evaluate against.

    Returns:
        List of violation messages. Empty if within limits.
    """
    if request.params is None:
        return []

    try:
        serialized = serialize_deterministic(request.params)
        size = len(serialized.encode("utf-8"))
        if size > policy.max_param_bytes:
            return [
                f"Params size ({size} bytes) exceeds maximum "
                f"({policy.max_param_bytes} bytes)"
            ]
    except Exception as e:
        return [f"Failed to serialize params: {e}"]

    return []


def check_intent_length(
    request: KernelRequest, policy: JurisdictionPolicy
) -> list[str]:
    """Check if intent length is within limits.

    Args:
        request: The request to check.
        policy: The policy to evaluate against.

    Returns:
        List of violation messages. Empty if within limits.
    """
    if request.intent and len(request.intent) > policy.max_intent_length:
        return [
            f"Intent length ({len(request.intent)}) exceeds maximum "
            f"({policy.max_intent_length})"
        ]
    return []


def check_tool_call_structure(request: KernelRequest) -> list[str]:
    """Check if tool call structure is valid.

    Args:
        request: The request to check.

    Returns:
        List of violation messages. Empty if valid.
    """
    if request.tool_call is None:
        return []

    violations = []

    if isinstance(request.tool_call, ToolCall):
        if not request.tool_call.name:
            violations.append("Tool call name is empty")
    elif isinstance(request.tool_call, dict):
        if not request.tool_call.get("name"):
            violations.append("Tool call name is empty")
        if "params" in request.tool_call:
            if not isinstance(request.tool_call.get("params"), dict):
                violations.append("Tool call params must be a dictionary")
    else:
        violations.append("Tool call has invalid structure")

    return violations


def evaluate_policy(
    request: KernelRequest,
    policy: JurisdictionPolicy,
) -> PolicyResult:
    """Evaluate all policy rules against a request.

    Args:
        request: The request to evaluate.
        policy: The policy to evaluate against.

    Returns:
        PolicyResult with allowed status and any violations.
    """
    all_violations: list[str] = []

    # Run all checks
    all_violations.extend(check_required_fields(request, policy))
    all_violations.extend(check_actor_allowed(request, policy))
    all_violations.extend(check_tool_allowed(request, policy))
    all_violations.extend(check_param_size(request, policy))
    all_violations.extend(check_intent_length(request, policy))
    all_violations.extend(check_tool_call_structure(request))

    return PolicyResult(
        allowed=len(all_violations) == 0,
        violations=all_violations,
    )
