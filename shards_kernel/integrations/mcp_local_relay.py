"""Official MCP SDK v2 stdio relay to the authenticated loopback operator.

The relay is an intentionally narrow *MCP client-facing* process. It holds
ONE independently enrolled agent bearer injected by its trusted launcher,
never an operator bearer or permit-signing key. It does not start a kernel,
issue permits, route arbitrary URLs, or expose privileged HTTP endpoints.

This is NOT a network-accessible/remote MCP gateway.
"""

from __future__ import annotations

import http.client
import json
import os
from secrets import token_hex
from typing import Any

try:
    # SDK owns JSON-RPC framing, lifecycle, listing and stdio transport.
    from mcp.server import MCPServer
    from mcp.types import CallToolResult, TextContent
except ImportError:  # Optional dependency; base kernel remains Python 3.9+.
    MCPServer = None
    CallToolResult = None
    TextContent = None

_MAX_PAYLOAD_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_ALLOWED_REFERENCE_TOOLS = frozenset({"echo", "add"})


def _actor_from_token(token: str) -> str:
    """Extract only a routing label; authority comes from HTTP token proof."""
    if (
        not isinstance(token, str)
        or not token.isascii()
        or not 40 <= len(token) <= 640
        or any(ch.isspace() for ch in token)
        or token.count(".") != 1
    ):
        raise ValueError("One agent-labelled, high-entropy credential is required")
    actor, random_secret = token.split(".", 1)
    if (
        not 1 <= len(actor) <= 128
        or not all(ch.isalnum() or ch in "-_" for ch in actor)
        or not 32 <= len(random_secret) <= 512
    ):
        raise ValueError("Agent credential label or secret has an unsafe format")
    return actor


def _reply(body: dict[str, Any], *, error: bool) -> Any:
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=json.dumps(body, sort_keys=True, separators=(",", ":")),
            )
        ],
        is_error=error,
    )


def _invoke_local_operator(
    *,
    port: int,
    bearer: str,
    actor: str,
    name: str,
    arguments: dict[str, Any],
    permit: dict[str, Any] | None,
) -> Any:
    """Transmit exactly one governed POST /submit; no retries or redirects."""
    request_id = "mcp-relay-" + token_hex(16)
    if name not in _ALLOWED_REFERENCE_TOOLS:
        return _reply({"request_id": request_id, "error": "Tool not available"}, error=True)
    if not isinstance(arguments, dict) or (permit is not None and not isinstance(permit, dict)):
        return _reply({"request_id": request_id, "error": "Invalid arguments or permit"}, error=True)

    # NEVER accept actor, destination, headers, token, request_id or privileged
    # endpoint from MCP arguments. The signed HTTP operator is the authority.
    payload = {
        "request_id": request_id,
        "actor": actor,
        "intent": "governed MCP local tool invocation",
        "tool_call": {"name": name, "params": arguments},
        "params": arguments,
    }
    if permit is not None:
        payload["permit"] = permit
    try:
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        return _reply({"request_id": request_id, "error": "Non-JSON request arguments"}, error=True)
    if len(body) > _MAX_PAYLOAD_BYTES:
        return _reply({"request_id": request_id, "error": "Request too large"}, error=True)

    # Literal loopback destination and fixed path: not a generic network proxy,
    # not an SSRF primitive, and not a redirect-capable HTTP client.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(
            "POST",
            "/submit",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + bearer,
            },
        )
        response = conn.getresponse()
        content = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(content) > _MAX_RESPONSE_BYTES:
            raise ValueError("Oversized operator response")
        if response.status != 200:
            return _reply(
                {"request_id": request_id, "error": "Operator rejected request", "http_status": response.status},
                error=True,
            )
        receipt = json.loads(content.decode("utf-8"))
        if not isinstance(receipt, dict) or receipt.get("request_id") != request_id:
            raise ValueError("Uncorrelated operator receipt")
        # Only a verified kernel ALLOW is considered successful. Do not
        # equate HTTP 200 with permission to execute.
        if receipt.get("decision") != "ALLOW":
            return _reply(
                {"request_id": request_id, "decision": "DENY", "error": str(receipt.get("error") or "Denied")},
                error=True,
            )
        return _reply(
            {"request_id": request_id, "decision": "ALLOW", "result": receipt.get("result")},
            error=False,
        )
    except (OSError, http.client.HTTPException, ValueError, UnicodeError, json.JSONDecodeError):
        # Fail closed with no bearer, request body or connection details.
        return _reply({"request_id": request_id, "error": "Local operator unavailable or invalid"}, error=True)
    finally:
        conn.close()


def create_local_mcp_agent_relay(*, port: int, agent_token: str) -> Any:
    """Create an official MCP v2 stdio server bound to ONE authenticated agent.

    The operator's independently signed v2 policy controls which tools
    this token can invoke; a second, separately signed Ed25519 permit is
    required for the exact tool arguments.
    """
    if MCPServer is None:
        raise RuntimeError("Install shards-kernel[mcp] on Python 3.11+")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Loopback operator port must be an integer between 1 and 65535")
    actor = _actor_from_token(agent_token)
    server = MCPServer("Shards-Kernel agent relay")

    @server.tool()
    def governed_execute(
        name: str,
        arguments: dict[str, Any],
        permit: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Submit a signed, scope-bound echo/add permit to the local operator."""
        return _invoke_local_operator(
            port=port,
            bearer=agent_token,
            actor=actor,
            name=name,
            arguments=arguments,
            permit=permit,
        )

    return server


def run_local_mcp_agent_relay(port: int) -> int:
    """Run stdio MCP; never print protocol-unrelated output on stdout."""
    token = os.environ.get("SHARDS_KERNEL_AGENT_TOKEN", "")
    try:
        server = create_local_mcp_agent_relay(port=port, agent_token=token)
    except (ValueError, RuntimeError):
        # Explicitly avoid displaying credentials in either stream.
        print("Local MCP agent relay refused startup", file=__import__("sys").stderr)
        return 2
    server.run(transport="stdio")
    return 0
