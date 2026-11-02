"""Agent-usable MCP client: strict input, process isolation and error behaviour."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from shards_kernel.cli import mcp_call


def _private_permit(tmp_path: Path, contents: str = '{"schema":"v2-test"}') -> Path:
    path = tmp_path / "issued-permit.json"
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.mark.skipif(os.name != "posix", reason="Private no-follow file handling is POSIX-only")
def test_read_signed_permit_from_private_file(tmp_path):
    assert mcp_call._read_private_permit(_private_permit(tmp_path)) == {"schema": "v2-test"}


@pytest.mark.skipif(os.name != "posix", reason="Private no-follow file handling is POSIX-only")
@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("[]", "nonempty"),
        ("{}", "nonempty"),
        ('{"x":1,"x":2}', "Duplicate"),
        ("broken", "Expecting"),
        ('{"x": 1e100000}', None),
        ("x" * (64 * 1024 + 1), "size invalid"),
    ],
)
def test_invalid_permit_document_fails_closed(tmp_path, content, reason):
    path = _private_permit(tmp_path, content)
    with pytest.raises((ValueError, json.JSONDecodeError), match=reason):
        mcp_call._read_private_permit(path)


@pytest.mark.skipif(os.name != "posix", reason="Private no-follow file handling is POSIX-only")
def test_permit_rejects_symlink_group_readable_and_relative(tmp_path):
    path = _private_permit(tmp_path)
    with pytest.raises(ValueError, match="Absolute"):
        mcp_call._read_private_permit(Path("relative.json"))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        mcp_call._read_private_permit(path)
    path.chmod(0o600)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        mcp_call._read_private_permit(alias)


@pytest.mark.parametrize(
    ("tool", "data", "valid"),
    [
        ("echo", '{"text":"hello"}', True),
        ("echo", '{"text":0}', False),
        ("echo", '{"text":"ok","extra":0}', False),
        ("echo", '["invalid"]', False),
        ("echo", '{"text":"ok","text":"duplicate"}', False),
        ("add", '{"a":5,"b":1.5}', True),
        ("add", '{"a":true,"b":5}', False),
        ("add", '{"a":5}', False),
        ("add", '{"a":1e10000,"b":1}', False),
        ("halt", "{}", False),
    ],
)
def test_only_typed_nonprivileged_arguments(tool, data, valid):
    if valid:
        assert mcp_call._arguments(tool, data)
    else:
        with pytest.raises(ValueError):
            mcp_call._arguments(tool, data)


class _FakeClient:
    def __init__(self, result, tools=None):
        self.result = result
        self.tools = ["governed_execute"] if tools is None else tools
        self.received = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def list_tools(self):
        return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in self.tools])

    async def call_tool(self, name, arguments):
        self.received = (name, arguments)
        return self.result


@pytest.mark.parametrize(
    ("decision", "is_error", "expected_exit"),
    [("ALLOW", False, 0), ("DENY", True, 2), ("ALLOW", True, 2), ("DENY", False, 2)],
)
def test_official_mcp_client_cannot_treat_denial_as_success(
    monkeypatch, decision, is_error, expected_exit
):
    receipt = json.dumps({"request_id": "mcp-relay-" + "a" * 32, "decision": decision, "result": "hello"})
    fake = _FakeClient(SimpleNamespace(
        content=[SimpleNamespace(type="text", text=receipt)],
        is_error=is_error,
    ))
    params = []
    fake_sdk = SimpleNamespace(
        Client=lambda transport: fake,
        StdioServerParameters=lambda **kw: params.append(kw) or kw,
    )
    monkeypatch.setitem(sys.modules, "mcp", fake_sdk)
    exit_code, result = asyncio.run(mcp_call._invoke(
        port=8765, token="agent-one." + "x" * 48, tool="echo",
        args={"text": "hello"}, permit={"signed": "placeholder"},
    ))
    assert exit_code == expected_exit
    assert result["decision"] == ("ALLOW" if expected_exit == 0 else "DENY")
    assert fake.received == ("governed_execute", {
        "name": "echo", "arguments": {"text": "hello"},
        "permit": {"signed": "placeholder"},
    })
    assert params[0]["args"] == ["-m", "shards_kernel", "mcp-relay", "--port", "8765"]
    assert set(params[0]["env"]) == {"SHARDS_KERNEL_AGENT_TOKEN"}
    assert "signed" not in json.dumps(result)
    assert "agent-one" not in json.dumps(result)


def test_unexpected_tool_catalogue_refuses_call(monkeypatch):
    fake = _FakeClient(SimpleNamespace(content=[], is_error=True), tools=["halt"])
    monkeypatch.setitem(sys.modules, "mcp", SimpleNamespace(
        Client=lambda _: fake, StdioServerParameters=lambda **kw: kw,
    ))
    with pytest.raises(ValueError, match="catalogue"):
        asyncio.run(mcp_call._invoke(
            port=8765, token="agent-one." + "x" * 48, tool="echo",
            args={"text": "hi"}, permit={"signed": True},
        ))
    assert fake.received is None


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "mkfifo"), reason="POSIX only")
def test_private_named_pipe_fails_without_waiting_for_writer(tmp_path):
    pipe = tmp_path / "permit.fifo"
    os.mkfifo(pipe, 0o600)
    with pytest.raises(ValueError, match="permissions"):
        mcp_call._read_private_permit(pipe)


@pytest.mark.parametrize(
    ("tool", "receipt"),
    [
        ("echo", {"decision": "ALLOW", "result": "ok"}),
        ("echo", {"request_id": "bad", "decision": "ALLOW", "result": "ok"}),
        ("echo", {"request_id": "mcp-relay-" + "a" * 32, "decision": "ALLOW"}),
        ("echo", {"request_id": "mcp-relay-" + "a" * 32, "decision": "ALLOW", "result": 5}),
        ("add", {"request_id": "mcp-relay-" + "a" * 32, "decision": "ALLOW", "result": True}),
        ("add", {"request_id": "mcp-relay-" + "a" * 32, "decision": "ALLOW", "result": "5"}),
    ],
)
def test_incomplete_or_wrong_type_allow_receipts_are_refused(monkeypatch, tool, receipt):
    fake = _FakeClient(SimpleNamespace(
        content=[SimpleNamespace(type="text", text=json.dumps(receipt))],
        is_error=False,
    ))
    monkeypatch.setitem(sys.modules, "mcp", SimpleNamespace(
        Client=lambda _: fake, StdioServerParameters=lambda **kwargs: kwargs,
    ))
    with pytest.raises(ValueError, match="receipt"):
        asyncio.run(mcp_call._invoke(
            port=8765, token="agent-one." + "x" * 48,
            tool=tool, args={"text": "ok"} if tool == "echo" else {"a": 2, "b": 3},
            permit={"signed": True},
        ))


@pytest.mark.parametrize("contents", [
    [],
    [SimpleNamespace(type="blob", text="bad")],
    [SimpleNamespace(type="text", text="{}"), SimpleNamespace(type="text", text="{}")],
    [SimpleNamespace(type="text", text='"not a receipt"')],
    [SimpleNamespace(type="text", text="x" * (64 * 1024 + 1))],
])
def test_invalid_mcp_response_fails_closed(monkeypatch, contents):
    fake = _FakeClient(SimpleNamespace(content=contents, is_error=False))
    monkeypatch.setitem(sys.modules, "mcp", SimpleNamespace(
        Client=lambda _: fake, StdioServerParameters=lambda **kw: kw,
    ))
    with pytest.raises((ValueError, json.JSONDecodeError)):
        asyncio.run(mcp_call._invoke(
            port=8765, token="agent-one." + "x" * 48, tool="echo",
            args={"text": "ok"}, permit={"signed": True},
        ))


@pytest.mark.skipif(os.name != "posix", reason="Local private permit requirement is POSIX-only")
def test_mcp_call_cli_passes_no_keys_to_agent_and_outputs_allow(
    tmp_path, monkeypatch, capsys
):
    path = _private_permit(tmp_path)
    token = "agent-one." + secrets.token_urlsafe(48)
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_TOKEN", token)
    observed = {}

    async def fake_invoke(**kwargs):
        observed.update(kwargs)
        return 0, {"decision": "ALLOW", "request_id": "safe", "result": 5}

    monkeypatch.setattr(mcp_call, "_invoke", fake_invoke)
    assert mcp_call.main([
        "--port", "8765", "--tool", "add",
        "--arguments-json", '{"a":2,"b":3}', "--permit-file", str(path),
    ]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["result"] == 5
    assert token not in output
    assert observed["token"] == token
    assert observed["permit"] == {"schema": "v2-test"}


@pytest.mark.parametrize("port", ["0", "65536"])
def test_invalid_port_rejected_before_any_transport(monkeypatch, capsys, port):
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_TOKEN", "agent-one." + "x" * 48)
    assert mcp_call.main([
        "--port", port, "--tool", "echo", "--arguments-json", '{"text":"hi"}',
        "--permit-file", "/file-not-used.json",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["decision"] == "DENY"


def test_missing_agent_token_rejected_without_logging_sensitive_data(capsys, monkeypatch):
    monkeypatch.delenv("SHARDS_KERNEL_AGENT_TOKEN", raising=False)
    assert mcp_call.main([
        "--port", "8765", "--tool", "echo", "--arguments-json", '{"text":"hi"}',
        "--permit-file", "/file-not-used.json",
    ]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "decision": "DENY", "error": "Invalid client configuration",
    }


@pytest.mark.parametrize("raw", ['{"a":NaN,"b":1}', '{"a":Infinity,"b":1}', '{"a":-Infinity,"b":1}'])
def test_nonfinite_json_constants_are_rejected(raw):
    with pytest.raises(ValueError, match="Non-finite"):
        mcp_call._arguments("add", raw)


def test_successful_numeric_add_requires_correlated_typed_receipt(monkeypatch):
    receipt = json.dumps({
        "request_id": "mcp-relay-" + "c" * 32,
        "decision": "ALLOW",
        "result": 5,
    })
    fake = _FakeClient(SimpleNamespace(
        content=[SimpleNamespace(type="text", text=receipt)],
        is_error=False,
    ))
    monkeypatch.setitem(sys.modules, "mcp", SimpleNamespace(
        Client=lambda _: fake, StdioServerParameters=lambda **kw: kw,
    ))
    status, result = asyncio.run(mcp_call._invoke(
        port=8765, token="agent-one." + "x" * 48, tool="add",
        args={"a": 2, "b": 3}, permit={"signed": "approved"},
    ))
    assert status == 0
    assert result["result"] == 5
    assert result["request_id"].startswith("mcp-relay-")


@pytest.mark.skipif(os.name != "posix", reason="Private POSIX file checks")
def test_invalid_permit_utf8_fails_closed(tmp_path):
    path = tmp_path / "bad-permit.json"
    path.write_bytes(bytes((0xFF, 0xFE)))
    path.chmod(0o600)
    with pytest.raises(UnicodeDecodeError):
        mcp_call._read_private_permit(path)


@pytest.mark.skipif(os.name != "posix", reason="Private POSIX permit checks")
def test_sdk_process_exception_is_redacted_as_denial(tmp_path, monkeypatch, capsys):
    path = _private_permit(tmp_path)
    token = "agent-one." + "x" * 48
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_TOKEN", token)

    async def failing_transport(**_kwargs):
        raise RuntimeError("internal transport carried a secret")

    monkeypatch.setattr(mcp_call, "_invoke", failing_transport)
    assert mcp_call.main([
        "--port", "8765", "--tool", "echo",
        "--arguments-json", '{"text":"ok"}', "--permit-file", str(path),
    ]) == 2
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "decision": "DENY", "error": "Local MCP transport failed",
    }
    assert "secret" not in output and token not in output
