"""
Shards-Kernel MCP Integration

Adapter for Model Context Protocol (MCP) integration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable

from shards_kernel.common.types import KernelRequest, ToolCall, Decision
from shards_kernel.integrations.wire import boot_strict_kernel, evidence_to_mapping
from shards_kernel.permits import PermitToken
from shards_kernel.variants.base import BaseKernel
from shards_kernel.jurisdiction.policy import JurisdictionPolicy


@dataclass
class MCPTool:
    """MCP tool definition."""

    name: str
    description: str
    input_schema: Dict[str, Any]


@dataclass
class MCPToolCall:
    """MCP tool call from client."""

    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class MCPToolResult:
    """MCP tool result to return."""

    call_id: str
    content: Any
    is_error: bool = False


class MCPAdapter:
    """
    Adapter for MCP (Model Context Protocol) integration.

    Wraps a Shards-Kernel kernel to provide MCP-compatible interface.
    All tool calls are routed through the kernel for governance.

    Example:
        kernel = StrictKernel(kernel_id="mcp-kernel")
        adapter = MCPAdapter(kernel, actor="mcp-agent")

        # Register tools
        adapter.register_tool("read_file", read_file_fn, {...})

        # Handle MCP tool call
        result = adapter.handle_tool_call(mcp_call)
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "mcp-agent",
    ):
        self.kernel = kernel
        self.actor = actor
        self._tools: Dict[str, Callable] = {}
        self._tool_schemas: Dict[str, MCPTool] = {}

    def register_tool(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Register a tool for MCP.

        Args:
            name: Tool name
            handler: Function to execute
            description: Tool description
            input_schema: JSON schema for inputs
        """
        self._tools[name] = handler
        dispatcher = getattr(self.kernel, "_dispatcher", None)
        if dispatcher is not None and not dispatcher.registry.has(name):
            dispatcher.registry.register(name, handler, description)
        self._tool_schemas[name] = MCPTool(
            name=name,
            description=description,
            input_schema=input_schema or {"type": "object", "properties": {}},
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """
        List available tools in MCP format.

        Returns:
            List of tool definitions
        """
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            }
            for tool in self._tool_schemas.values()
        ]

    def handle_tool_call(
        self,
        call: MCPToolCall,
        intent: Optional[str] = None,
        permit_token: Optional[PermitToken] = None,
    ) -> MCPToolResult:
        """
        Handle an MCP tool call through the kernel.

        Args:
            call: The MCP tool call
            intent: Optional intent description

        Returns:
            MCP tool result
        """
        arguments = dict(call.arguments)
        request = KernelRequest(
            request_id=call.id,
            ts_ms=self.kernel.config.clock.now_ms(),
            actor=self.actor,
            intent=intent or f"Execute {call.name}",
            tool_call=ToolCall(name=call.name, params=arguments),
            params=arguments,
        )

        receipt = self.kernel.submit(request, permit_token=permit_token)

        if receipt.decision == Decision.ALLOW:
            return MCPToolResult(
                call_id=call.id,
                content=receipt.tool_result,
                is_error=False,
            )
        else:
            return MCPToolResult(
                call_id=call.id,
                content={"error": receipt.error or "Request denied"},
                is_error=True,
            )

    def handle_tool_call_json(
        self,
        call_json: Dict[str, Any],
        intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Handle an MCP tool call from JSON.

        Args:
            call_json: Tool call as dict
            intent: Optional intent description

        Returns:
            Result as dict
        """
        call = MCPToolCall(
            id=call_json["id"],
            name=call_json["name"],
            arguments=call_json.get("arguments", {}),
        )

        result = self.handle_tool_call(call, intent)

        return {
            "call_id": result.call_id,
            "content": result.content,
            "is_error": result.is_error,
        }

    def export_evidence(self) -> Dict[str, Any]:
        """Export audit evidence from the kernel."""
        return evidence_to_mapping(self.kernel.export_evidence())

    def halt(self) -> None:
        """Halt the kernel."""
        self.kernel.halt("operator halt")


class MCPServer:
    """
    Simple MCP server implementation.

    Provides stdio-based MCP server that routes
    all tool calls through a Shards-Kernel kernel.

    Example:
        kernel = StrictKernel(kernel_id="mcp-server")
        server = MCPServer(kernel)
        server.run()  # Blocks, reads from stdin
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "mcp-client",
    ):
        self.adapter = MCPAdapter(kernel, actor)

    def register_tool(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a tool."""
        self.adapter.register_tool(name, handler, description, input_schema)

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle an MCP message.

        Args:
            message: MCP JSON-RPC message

        Returns:
            Response message
        """
        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.adapter.list_tools()},
            }

        elif method == "tools/call":
            call = MCPToolCall(
                id=params.get("id", str(msg_id)),
                name=params["name"],
                arguments=params.get("arguments", {}),
            )
            permit_payload = params.get("permit")
            permit = None
            if permit_payload:
                from shards_kernel.integrations.wire import permit_from_mapping

                permit = permit_from_mapping(permit_payload)
            result = self.adapter.handle_tool_call(call, permit_token=permit)

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result.content)}],
                    "isError": result.is_error,
                },
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }

    def run(self) -> None:
        """
        Run the MCP server (stdio mode).

        Reads JSON-RPC messages from stdin,
        writes responses to stdout.
        """
        import sys

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                message = json.loads(line)
                response = self.handle_message(message)

                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

            except json.JSONDecodeError:
                continue
            except KeyboardInterrupt:
                break


def create_mcp_adapter(
    kernel_id: str = "mcp-kernel",
    actor: str = "mcp-agent",
    policy: Optional[JurisdictionPolicy] = None,
) -> MCPAdapter:
    """
    Create an MCP adapter with a new kernel.

    Args:
        kernel_id: Kernel identifier
        actor: Actor name for MCP calls
        policy: Jurisdiction policy

    Returns:
        Configured MCP adapter
    """
    kernel = boot_strict_kernel(kernel_id)
    if policy is not None:
        kernel.set_policy(policy)
    return MCPAdapter(kernel, actor)
