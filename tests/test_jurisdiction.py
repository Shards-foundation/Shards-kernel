"""Tests for jurisdiction policy and rules."""

import unittest

from shards_kernel.common.types import KernelRequest, ToolCall
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.jurisdiction.rules import (
    check_actor_allowed,
    check_tool_allowed,
    check_required_fields,
    check_param_size,
    evaluate_policy,
)


class TestJurisdictionPolicy(unittest.TestCase):
    """Test cases for JurisdictionPolicy."""

    def test_default_policy(self) -> None:
        """Default policy allows all actors and tools."""
        policy = JurisdictionPolicy.default()
        self.assertTrue(policy.allows_actor("any_actor"))
        self.assertTrue(policy.allows_tool("any_tool"))

    def test_strict_policy(self) -> None:
        """Strict policy denies all by default."""
        policy = JurisdictionPolicy.strict()
        self.assertFalse(policy.allows_actor("any_actor"))
        self.assertFalse(policy.allows_tool("any_tool"))

    def test_specific_actors(self) -> None:
        """Policy with specific actors only allows those actors."""
        policy = JurisdictionPolicy(
            allowed_actors=frozenset({"alice", "bob"}),
            allowed_tools=frozenset({"*"}),
        )
        self.assertTrue(policy.allows_actor("alice"))
        self.assertTrue(policy.allows_actor("bob"))
        self.assertFalse(policy.allows_actor("charlie"))

    def test_specific_tools(self) -> None:
        """Policy with specific tools only allows those tools."""
        policy = JurisdictionPolicy(
            allowed_actors=frozenset({"*"}),
            allowed_tools=frozenset({"echo", "add"}),
        )
        self.assertTrue(policy.allows_tool("echo"))
        self.assertTrue(policy.allows_tool("add"))
        self.assertFalse(policy.allows_tool("delete"))

    def test_from_dict(self) -> None:
        """Policy can be created from dictionary."""
        data = {
            "allowed_actors": ["user1"],
            "allowed_tools": ["tool1"],
            "max_param_bytes": 1024,
        }
        policy = JurisdictionPolicy.from_dict(data)
        self.assertTrue(policy.allows_actor("user1"))
        self.assertFalse(policy.allows_actor("user2"))
        self.assertEqual(policy.max_param_bytes, 1024)


class TestJurisdictionRules(unittest.TestCase):
    """Test cases for jurisdiction rules."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.policy = JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}),
            allowed_tools=frozenset({"echo"}),
            required_fields=frozenset({"request_id", "actor", "intent"}),
        )
        self.valid_request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test intent",
            tool_call=ToolCall(name="echo", params={"text": "hello"}),
        )

    def test_check_actor_allowed(self) -> None:
        """Allowed actor passes check."""
        errors = check_actor_allowed(self.valid_request, self.policy)
        self.assertEqual(errors, [])

    def test_check_actor_denied(self) -> None:
        """Denied actor fails check."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="bob",
            intent="test",
        )
        errors = check_actor_allowed(request, self.policy)
        self.assertEqual(len(errors), 1)
        self.assertIn("bob", errors[0])

    def test_check_tool_allowed(self) -> None:
        """Allowed tool passes check."""
        errors = check_tool_allowed(self.valid_request, self.policy)
        self.assertEqual(errors, [])

    def test_check_tool_denied(self) -> None:
        """Denied tool fails check."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test",
            tool_call=ToolCall(name="delete", params={}),
        )
        errors = check_tool_allowed(request, self.policy)
        self.assertEqual(len(errors), 1)
        self.assertIn("delete", errors[0])

    def test_check_required_fields(self) -> None:
        """Valid request passes required fields check."""
        errors = check_required_fields(self.valid_request, self.policy)
        self.assertEqual(errors, [])

    def test_check_required_fields_missing(self) -> None:
        """Missing required field fails check."""
        request = KernelRequest(
            request_id="",
            ts_ms=1000,
            actor="alice",
            intent="test",
        )
        errors = check_required_fields(request, self.policy)
        self.assertTrue(len(errors) > 0)

    def test_check_param_size(self) -> None:
        """Small params pass size check."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="test",
            params={"key": "value"},
        )
        errors = check_param_size(request, self.policy)
        self.assertEqual(errors, [])

    def test_evaluate_policy_allowed(self) -> None:
        """Valid request passes full policy evaluation."""
        result = evaluate_policy(self.valid_request, self.policy)
        self.assertTrue(result.allowed)
        self.assertEqual(result.violations, [])

    def test_evaluate_policy_denied(self) -> None:
        """Invalid request fails policy evaluation."""
        request = KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="bob",
            intent="test",
        )
        result = evaluate_policy(request, self.policy)
        self.assertFalse(result.allowed)
        self.assertTrue(len(result.violations) > 0)


if __name__ == "__main__":
    unittest.main()
