"""MCP JSON-RPC server contract tests."""

import io
import json
import sys

from shards_kernel.integrations.mcp_adapter import MCPServer
from shards_kernel.integrations.wire import boot_strict_kernel


def test_mcp_server_list_call_and_unknown_method():
    server = MCPServer(boot_strict_kernel("mcp-server-test"))
    server.register_tool("echo", lambda value: value, description="Echo")
    listed = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert listed["result"]["tools"][0]["name"] == "echo"

    called = server.handle_message({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"value": "x"}},
    })
    assert called["id"] == 2
    assert called["result"]["isError"] is True

    unknown = server.handle_message({"id": 3, "method": "no/such/method"})
    assert unknown["error"]["code"] == -32601


def test_mcp_server_stdio_skips_bad_json_and_exits_on_eof(monkeypatch, capsys):
    server = MCPServer(boot_strict_kernel("mcp-stdio-test"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        "{bad json}\n" + json.dumps({"id": 7, "method": "tools/list"}) + "\n"
    ))
    server.run()
    output = capsys.readouterr().out.strip().splitlines()
    assert len(output) == 1
    assert json.loads(output[0])["id"] == 7
