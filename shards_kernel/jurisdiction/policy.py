"""Jurisdiction policy definitions.

A JurisdictionPolicy defines the boundaries within which requests are allowed.
Requests that fall outside these boundaries are denied.
"""

from dataclasses import dataclass, field
from typing import FrozenSet

from shards_kernel.common.types import KernelState


@dataclass(frozen=True)
class JurisdictionPolicy:
    """Policy defining allowed actors, tools, and constraints.

    A policy is immutable once created. All fields use frozen collections
    to prevent modification.
    """

    allowed_actors: FrozenSet[str] = field(default_factory=frozenset)
    allowed_tools: FrozenSet[str] = field(default_factory=frozenset)
    allowed_states: FrozenSet[KernelState] = field(
        default_factory=lambda: frozenset(
            {
                KernelState.IDLE,
                KernelState.VALIDATING,
                KernelState.ARBITRATING,
                KernelState.EXECUTING,
                KernelState.AUDITING,
                KernelState.COMPLETED,
            }
        )
    )
    required_fields: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"request_id", "actor", "intent"})
    )
    max_param_bytes: int = 65536
    max_intent_length: int = 4096
    allow_intent_only: bool = False

    @classmethod
    def default(cls) -> "JurisdictionPolicy":
        """Create a default policy with common settings.

        Returns:
            A policy with wildcard actor/tool access.
        """
        return cls(
            allowed_actors=frozenset({"*"}),
            allowed_tools=frozenset({"*"}),
        )

    @classmethod
    def strict(cls) -> "JurisdictionPolicy":
        """Create a strict policy requiring explicit allowlists.

        Returns:
            A policy with empty allowlists (denies all by default).
        """
        return cls(
            allowed_actors=frozenset(),
            allowed_tools=frozenset(),
            allow_intent_only=False,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "JurisdictionPolicy":
        """Create a policy from a dictionary.

        Args:
            data: Dictionary with policy fields.

        Returns:
            JurisdictionPolicy instance.
        """
        allowed_states = data.get("allowed_states", [])
        if allowed_states:
            allowed_states = frozenset(
                KernelState(s) if isinstance(s, str) else s for s in allowed_states
            )
        else:
            allowed_states = frozenset(
                {
                    KernelState.IDLE,
                    KernelState.VALIDATING,
                    KernelState.ARBITRATING,
                    KernelState.EXECUTING,
                    KernelState.AUDITING,
                    KernelState.COMPLETED,
                }
            )

        return cls(
            allowed_actors=frozenset(data.get("allowed_actors", [])),
            allowed_tools=frozenset(data.get("allowed_tools", [])),
            allowed_states=allowed_states,
            required_fields=frozenset(
                data.get("required_fields", ["request_id", "actor", "intent"])
            ),
            max_param_bytes=data.get("max_param_bytes", 65536),
            max_intent_length=data.get("max_intent_length", 4096),
            allow_intent_only=data.get("allow_intent_only", False),
        )

    def allows_actor(self, actor: str) -> bool:
        """Check if an actor is allowed.

        Args:
            actor: Actor identifier to check.

        Returns:
            True if actor is allowed, False otherwise.
        """
        if "*" in self.allowed_actors:
            return True
        return actor in self.allowed_actors

    def allows_tool(self, tool: str) -> bool:
        """Check if a tool is allowed.

        Args:
            tool: Tool name to check.

        Returns:
            True if tool is allowed, False otherwise.
        """
        if "*" in self.allowed_tools:
            return True
        return tool in self.allowed_tools

    def allows_state(self, state: KernelState) -> bool:
        """Check if operations are allowed in a state.

        Args:
            state: Kernel state to check.

        Returns:
            True if state allows operations, False otherwise.
        """
        return state in self.allowed_states
