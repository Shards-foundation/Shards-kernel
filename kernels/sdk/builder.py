"""
KERNELS SDK Builders

Fluent builders for constructing requests and policies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from kernels.common.types import Request, ToolCall
from kernels.jurisdiction.policy import JurisdictionPolicy


class RequestBuilder:
    """
    Fluent builder for constructing requests.

    Example:
        request = (
            RequestBuilder()
            .with_actor("my-agent")
            .with_intent("Read a file")
            .with_tool("read_file", {"path": "/config.yaml"})
            .build()
        )
    """

    def __init__(self):
        self._request_id: Optional[str] = None
        self._actor: Optional[str] = None
        self._intent: Optional[str] = None
        self._tool_name: Optional[str] = None
        self._tool_params: Dict[str, Any] = {}
        self._evidence: List[str] = []
        self._constraints: Dict[str, Any] = {}
        self._metadata: Dict[str, Any] = {}

    def with_id(self, request_id: str) -> RequestBuilder:
        """Set request ID."""
        self._request_id = request_id
        return self

    def with_actor(self, actor: str) -> RequestBuilder:
        """Set actor."""
        self._actor = actor
        return self

    def with_intent(self, intent: str) -> RequestBuilder:
        """Set intent."""
        self._intent = intent
        return self

    def with_tool(
        self, name: str, params: Optional[Dict[str, Any]] = None
    ) -> RequestBuilder:
        """Set tool call."""
        self._tool_name = name
        self._tool_params = params or {}
        return self

    def with_param(self, key: str, value: Any) -> RequestBuilder:
        """Add a tool parameter."""
        self._tool_params[key] = value
        return self

    def with_evidence(self, *evidence_ids: str) -> RequestBuilder:
        """Add evidence IDs."""
        self._evidence.extend(evidence_ids)
        return self

    def with_constraints(
        self,
        scope: Optional[str] = None,
        non_goals: Optional[List[str]] = None,
        success_criteria: Optional[List[str]] = None,
    ) -> RequestBuilder:
        """Set constraints for dual-channel kernel."""
        if scope:
            self._constraints["scope"] = scope
        if non_goals:
            self._constraints["non_goals"] = non_goals
        if success_criteria:
            self._constraints["success_criteria"] = success_criteria
        return self

    def with_metadata(self, key: str, value: Any) -> RequestBuilder:
        """Add metadata."""
        self._metadata[key] = value
        return self

    def build(self) -> Request:
        """
        Build the request.

        Returns:
            Constructed Request object

        Raises:
            ValueError: If required fields are missing
        """
        if not self._actor:
            raise ValueError("actor is required")
        if not self._intent:
            raise ValueError("intent is required")

        request_id = self._request_id or f"req-{uuid.uuid4().hex[:8]}"

        params = dict(self._tool_params)
        if self._constraints:
            params["constraints"] = dict(self._constraints)

        tool_call = None
        if self._tool_name:
            tool_call = ToolCall(name=self._tool_name, params=dict(params))

        evidence = "\n".join(self._evidence) if self._evidence else None

        return Request(
            request_id=request_id,
            ts_ms=0,
            actor=self._actor,
            intent=self._intent,
            tool_call=tool_call,
            params=params,
            evidence=evidence,
        )

    def reset(self) -> RequestBuilder:
        """Reset builder to initial state."""
        self._request_id = None
        self._actor = None
        self._intent = None
        self._tool_name = None
        self._tool_params = {}
        self._evidence = []
        self._constraints = {}
        self._metadata = {}
        return self


class PolicyBuilder:
    """
    Fluent builder for constructing jurisdiction policies.

    Example:
        policy = (
            PolicyBuilder()
            .allow_actors("agent-001", "agent-002")
            .allow_tools("read_file", "write_file")
            .require_tool_call()
            .with_max_intent_length(500)
            .build()
        )
    """

    def __init__(self):
        self._allowed_actors: List[str] = []
        self._allowed_tools: List[str] = []
        self._require_tool_call: bool = True
        self._max_intent_length: int = 1000
        self._custom_rules: List = []

    def allow_actor(self, actor: str) -> PolicyBuilder:
        """Allow a single actor."""
        self._allowed_actors.append(actor)
        return self

    def allow_actors(self, *actors: str) -> PolicyBuilder:
        """Allow multiple actors."""
        self._allowed_actors.extend(actors)
        return self

    def allow_tool(self, tool: str) -> PolicyBuilder:
        """Allow a single tool."""
        self._allowed_tools.append(tool)
        return self

    def allow_tools(self, *tools: str) -> PolicyBuilder:
        """Allow multiple tools."""
        self._allowed_tools.extend(tools)
        return self

    def require_tool_call(self, required: bool = True) -> PolicyBuilder:
        """Set whether tool_call is required."""
        self._require_tool_call = required
        return self

    def with_max_intent_length(self, length: int) -> PolicyBuilder:
        """Set maximum intent length."""
        self._max_intent_length = length
        return self

    def with_custom_rule(self, rule) -> PolicyBuilder:
        """Add a custom rule function."""
        self._custom_rules.append(rule)
        return self

    def build(self) -> JurisdictionPolicy:
        """
        Build the policy.

        Returns:
            Constructed JurisdictionPolicy object
        """
        if self._custom_rules:
            raise ValueError(
                "JurisdictionPolicy has no custom_rules field. "
                "Use the built-in actor, tool, and size checks."
            )
        return JurisdictionPolicy(
            allowed_actors=frozenset(self._allowed_actors),
            allowed_tools=frozenset(self._allowed_tools),
            max_intent_length=self._max_intent_length,
            allow_intent_only=not self._require_tool_call,
        )

    def reset(self) -> PolicyBuilder:
        """Reset builder to initial state."""
        self._allowed_actors = []
        self._allowed_tools = []
        self._require_tool_call = True
        self._max_intent_length = 1000
        self._custom_rules = []
        return self

    @classmethod
    def strict(cls) -> PolicyBuilder:
        """Create a builder pre-configured for strict mode."""
        return cls().require_tool_call(True).with_max_intent_length(500)

    @classmethod
    def permissive(cls) -> PolicyBuilder:
        """Create a builder pre-configured for permissive mode."""
        return (
            cls()
            .allow_actors("*")
            .allow_tools("*")
            .require_tool_call(False)
            .with_max_intent_length(10000)
        )


class ToolCallBuilder:
    """
    Fluent builder for constructing tool calls.

    Example:
        tool_call = (
            ToolCallBuilder("read_file")
            .with_param("path", "/config.yaml")
            .with_param("encoding", "utf-8")
            .build()
        )
    """

    def __init__(self, name: str):
        self._name = name
        self._params: Dict[str, Any] = {}

    def with_param(self, key: str, value: Any) -> ToolCallBuilder:
        """Add a parameter."""
        self._params[key] = value
        return self

    def with_params(self, params: Dict[str, Any]) -> ToolCallBuilder:
        """Add multiple parameters."""
        self._params.update(params)
        return self

    def build(self) -> ToolCall:
        """Build the tool call."""
        return ToolCall(
            name=self._name,
            params=self._params,
        )


# Convenience functions


def request() -> RequestBuilder:
    """Create a new request builder."""
    return RequestBuilder()


def policy() -> PolicyBuilder:
    """Create a new policy builder."""
    return PolicyBuilder()


def tool_call(name: str) -> ToolCallBuilder:
    """Create a new tool call builder."""
    return ToolCallBuilder(name)
