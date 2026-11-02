"""One-shot agent MCP client to an existing signed, loopback-only operator.

This is an agent-side local client, NOT a remote MCP Gateway or a permit
issuer. The operator's independently enrolled token and signed permit must
already exist. Never take signing keys, operator tokens or arbitrary URLs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import stat
import sys
from pathlib import Path
from typing import Any

_MAX_PERMIT_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_TOOLS = frozenset({"echo", "add"})


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _strict_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON numbers are forbidden")
    return number


def _reject_constant(_value: str) -> None:
    raise ValueError("Non-finite JSON constants are forbidden")


def _json_object(raw: str) -> Any:
    return json.loads(
        raw, object_pairs_hook=_unique_pairs,
        parse_float=_strict_float, parse_constant=_reject_constant,
    )


def _read_private_permit(path: Path) -> dict[str, Any]:
    """Read a bounded, operator-owned permit through a no-follow descriptor."""
    if not path.is_absolute() or os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Absolute private POSIX permit file required")
    fd = os.open(
        str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_PERMIT_BYTES
            or metadata.st_mode & 0o077
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("Permit file ownership, permissions or size invalid")
        with os.fdopen(os.dup(fd), "rb") as stream:
            content = stream.read(_MAX_PERMIT_BYTES + 1)
        if len(content) > _MAX_PERMIT_BYTES:
            raise ValueError("Permit file too large")
    finally:
        os.close(fd)
    permit = _json_object(content.decode("utf-8"))
    if not isinstance(permit, dict) or not permit:
        raise ValueError("Signed permit must be a nonempty JSON object")
    return permit


def _arguments(tool: str, raw: str) -> dict[str, Any]:
    if tool not in _TOOLS:
        raise ValueError("Only the built-in echo/add tools are supported")
    value = _json_object(raw)
    if not isinstance(value, dict):
        raise ValueError("Arguments must be a JSON object")
    if tool == "echo" and (set(value) != {"text"} or not isinstance(value["text"], str)):
        raise ValueError("echo requires exactly one text string")
    if tool == "add" and (
        set(value) != {"a", "b"} or any(type(value[k]) not in (int, float) for k in ("a", "b"))
    ):
        raise ValueError("add requires exactly two numeric arguments")
    return value


async def _invoke(
    *, port: int, token: str, tool: str, args: dict[str, Any],
    permit: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    # The official MCP SDK owns protocol negotiation, JSON-RPC and stdio.
    from mcp import Client, StdioServerParameters

    transport = StdioServerParameters(
        command=sys.executable,
        args=["-m", "shards_kernel", "mcp-relay", "--port", str(port)],
        env={"SHARDS_KERNEL_AGENT_TOKEN": token},
    )
    async with Client(transport) as client:
        listing = await client.list_tools()
        if {item.name for item in listing.tools} != {"governed_execute"}:
            raise ValueError("Unexpected MCP tool catalogue")
        reply = await client.call_tool(
            "governed_execute", {"name": tool, "arguments": args, "permit": permit}
        )
        if len(reply.content) != 1 or getattr(reply.content[0], "type", None) != "text":
            raise ValueError("Invalid MCP tool response")
        raw_response = reply.content[0].text
        if len(raw_response.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            raise ValueError("Oversized MCP tool response")
        result = _json_object(raw_response)
        if not isinstance(result, dict):
            raise ValueError("Invalid MCP receipt")
        if not reply.is_error and result.get("decision") == "ALLOW":
            return 0, {
                "decision": "ALLOW",
                "request_id": result.get("request_id"),
                "result": result.get("result"),
            }
        return 2, {
            "decision": "DENY",
            "request_id": result.get("request_id"),
            "error": "Governed execution refused",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Call one locally governed MCP echo/add tool; no remote transport"
    )
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tool", choices=sorted(_TOOLS), required=True)
    parser.add_argument("--arguments-json", required=True)
    parser.add_argument("--permit-file", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        if not 1 <= options.port <= 65535:
            raise ValueError("Invalid local port")
        token = os.environ.get("SHARDS_KERNEL_AGENT_TOKEN", "")
        # The relay revalidates the token against the signed operator policy.
        from shards_kernel.integrations.mcp_local_relay import _actor_from_token

        _actor_from_token(token)
        args = _arguments(options.tool, options.arguments_json)
        permit = _read_private_permit(options.permit_file)
        status, response = asyncio.run(
            _invoke(port=options.port, token=token, tool=options.tool,
                    args=args, permit=permit)
        )
    except (OSError, ValueError, TypeError, ImportError, UnicodeError, json.JSONDecodeError):
        status, response = 2, {"decision": "DENY", "error": "Invalid client configuration"}
    except Exception:
        # SDK transport, process and protocol failures must never expose bearer,
        # permit or remote messages in public logs.
        status, response = 2, {"decision": "DENY", "error": "Local MCP transport failed"}
    print(json.dumps(response, separators=(",", ":"), sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
