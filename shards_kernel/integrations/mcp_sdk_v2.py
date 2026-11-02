"""Opt-in, official MCP Python SDK v2 adapter for *local stdio* processes.

The SDK owns protocol negotiation, framing and transport. The kernel remains
the sole authority for tool execution. Remote MCP authorization is deliberately
out of scope: do not expose this local adapter as an internet service.
"""

from __future__ import annotations

import json
import threading
from secrets import token_hex
from typing import Any, Callable, Mapping

from shards_kernel.integrations.mcp_adapter import MCPAdapter, MCPToolCall
from shards_kernel.integrations.wire import permit_from_mapping
from shards_kernel.variants.base import BaseKernel


def create_official_mcp_server(
    kernel: BaseKernel,
    *,
    actor: str,
    handlers: Mapping[str, Callable[..., Any]],
) -> Any:
    """Build an MCP v2 server with an explicit, kernel-governed tool allowlist.

    `actor` is set by the trusted local process, never supplied by an LLM.
    The incoming `permit` is a signed, narrowly scoped capability; this
    function does not issue permits or derive identity from the tool payload.
    """
    try:
        from mcp.server import MCPServer
        from mcp.types import CallToolResult, TextContent
    except ImportError as exc:
        raise RuntimeError(
            "Official MCP SDK v2 is required: install shards-kernel[mcp] on Python 3.11+"
        ) from exc

    if not isinstance(actor, str) or not actor.strip() or "*" in actor:
        raise ValueError("A concrete, trusted local actor identity is required")
    if not isinstance(handlers, Mapping) or not handlers:
        raise ValueError("At least one explicitly registered handler is required")

    # Never launch a gateway with the kernel's wildcard example policy.
    policy = kernel.policy
    if "*" in policy.allowed_actors or "*" in policy.allowed_tools:
        raise ValueError("MCP bridge requires explicit actor and tool allowlists")
    if actor not in policy.allowed_actors:
        raise ValueError("Local actor is not allowed by kernel policy")

    registry = kernel._dispatcher.registry
    for name, handler in handlers.items():
        if not isinstance(name, str) or not name.strip() or not callable(handler):
            raise ValueError("Every handler must have a nonempty name and be callable")
        if name not in policy.allowed_tools:
            raise ValueError("Handler is not on the kernel tool allowlist")
        if registry.has(name):
            raise ValueError("Tool name collides with an existing registry entry")

    adapter = MCPAdapter(kernel, actor=actor)
    for name, handler in handlers.items():
        adapter.register_tool(name, handler)

    lock = threading.RLock()
    server = MCPServer("Shards-Kernel")

    def result_response(result: Any, *, error: bool) -> CallToolResult:
        try:
            body = json.dumps(result, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return CallToolResult(
                content=[TextContent(type="text", text='{"error":"Result not JSON serializable"}')],
                is_error=True,
            )
        return CallToolResult(
            content=[TextContent(type="text", text=body)],
            is_error=error,
        )

    @server.tool()
    def governed_execute(
        name: str,
        arguments: dict[str, Any],
        permit: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Execute an allowlisted operation only after signed-permit governance."""
        if name not in handlers:
            return result_response({"error": "Tool not registered"}, error=True)
        if not isinstance(arguments, dict):
            return result_response({"error": "Invalid arguments"}, error=True)

        with lock:
            try:
                token = permit_from_mapping(permit) if permit is not None else None
            except (TypeError, ValueError, KeyError):
                return result_response({"error": "Invalid permit format"}, error=True)

            request_id = "mcp-" + token_hex(16)
            try:
                outcome = adapter.handle_tool_call(
                    MCPToolCall(id=request_id, name=name, arguments=arguments),
                    permit_token=token,
                )
            except Exception:
                # Never surface runtime exception details, credentials, or raw traces.
                return result_response(
                    {"request_id": request_id, "error": "Kernel operation failed"},
                    error=True,
                )
            return result_response(
                {
                    "request_id": request_id,
                    "result": outcome.content if not outcome.is_error else None,
                    "error": outcome.content if outcome.is_error else None,
                },
                error=outcome.is_error,
            )

    return server
