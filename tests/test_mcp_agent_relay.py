"""Official MCP v2 agents through real stdio processes to a signed local kernel."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request

import pytest

pytest.importorskip("mcp")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from mcp import Client, StdioServerParameters  # noqa: E402

from shards_kernel.integrations.auth import agent_token_kdf  # noqa: E402
from shards_kernel.integrations.mcp_local_relay import (  # noqa: E402
    _actor_from_token,
    _invoke_local_operator,
    create_local_mcp_agent_relay,
)
from shards_kernel.integrations.wire import permit_to_mapping  # noqa: E402
from shards_kernel.issuer import sign_operator_policy, sign_v2_permit  # noqa: E402
from shards_kernel.permits import PermitBuilder  # noqa: E402


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _sign_permit(issuer, actor, action, params):
    now = int(time.time() * 1000)
    return permit_to_mapping(sign_v2_permit(
        (
            PermitBuilder()
            .issuer("operator")
            .subject(actor)
            .jurisdiction("default")
            .action(action)
            .params(params)
            .max_executions(1)
            .valid_from_ms(now - 30_000)
            .valid_until_ms(now + 120_000)
            .proposal_hash("independent-approval-" + actor)
            .build_unsigned_v2(key_id="permit-issuer", audience="relay-test-kernel")
        ),
        issuer,
    ))


def _http_health(base):
    request = urllib.request.Request(base + "/health")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:  # nosec B310: loopback health probe
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _run_service_process(config_path):
    from shards_kernel.__main__ import main

    sys.argv = ["shards-kernel", "serve", "--config", str(config_path)]
    raise SystemExit(main())


def _start_service(config_path, base):
    proc = multiprocessing.get_context("spawn").Process(
        target=_run_service_process, args=(str(config_path),)
    )
    proc.start()
    for _ in range(100):
        if not proc.is_alive():
            _stop(proc)
            raise AssertionError("Signed local operator process exited before health")
        try:
            status, result = _http_health(base)
            if status == 200 and result["status"] == "healthy":
                return proc
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    _stop(proc)
    raise AssertionError("Signed operator service not healthy")


def _stop(proc):
    if proc.is_alive():
        proc.terminate()
    proc.join(timeout=8)
    if proc.is_alive():
        proc.kill()
        proc.join(timeout=8)
    assert not proc.is_alive()


def _fixture(tmp_path, monkeypatch):
    permit_issuer = Ed25519PrivateKey.generate()
    policy_issuer = Ed25519PrivateKey.generate()
    pepper = secrets.token_urlsafe(48)
    alpha = "agent-alpha." + secrets.token_urlsafe(48)
    beta = "agent-beta." + secrets.token_urlsafe(48)
    config = {
        "version": 2,
        "kernel_id": "relay-test-kernel",
        "tools": ["echo", "add"],
        "agents": [
            {
                "actor": "agent-alpha",
                "token_scrypt": agent_token_kdf(alpha, pepper.encode()),
                "allowed_tools": ["echo"],
            },
            {
                "actor": "agent-beta",
                "token_scrypt": agent_token_kdf(beta, pepper.encode()),
                "allowed_tools": ["add"],
            },
        ],
        "issuer_keys": [
            {
                "key_id": "permit-issuer",
                "issuer": "operator",
                "public_key_hex": permit_issuer.public_key().public_bytes_raw().hex(),
                "revoked": False,
            }
        ],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": _free_port(),
    }
    now = int(time.time() * 1000)
    policy = sign_operator_policy(
        config, policy_issuer,
        revision=1, issued_at_ms=now - 60_000,
        expires_at_ms=now + 600_000,
    )
    path = tmp_path / "signed-relay-policy.json"
    path.write_text(json.dumps(policy))
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", secrets.token_urlsafe(40))
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_AUTH_PEPPER", pepper)
    monkeypatch.setenv(
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
        policy_issuer.public_key().public_bytes_raw().hex(),
    )
    return config, path, permit_issuer, alpha, beta


def _client(port, token):
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "shards_kernel", "mcp-relay", "--port", str(port)],
        env={"SHARDS_KERNEL_AGENT_TOKEN": token},
    )


def _result(mcp_result):
    return json.loads(mcp_result.content[0].text)


@pytest.mark.skipif(os.name != "posix", reason="Operator SQLite audit lock is POSIX-only")
def test_two_real_mcp_stdio_clients_separate_signed_agent_identity_across_restart(
    tmp_path, monkeypatch
):
    config, signed_policy, issuer, token_alpha, token_beta = _fixture(tmp_path, monkeypatch)
    base = "http://127.0.0.1:" + str(config["port"])
    alpha_permit = _sign_permit(issuer, "agent-alpha", "echo", {"text": "hello"})
    beta_permit = _sign_permit(issuer, "agent-beta", "add", {"a": 2, "b": 3})
    alpha_call = {
        "name": "echo", "arguments": {"text": "hello"}, "permit": alpha_permit,
    }
    beta_call = {
        "name": "add", "arguments": {"a": 2, "b": 3}, "permit": beta_permit,
    }

    async def first_session():
        async with Client(_client(config["port"], token_alpha)) as alpha:
            async with Client(_client(config["port"], token_beta)) as beta:
                assert alpha.protocol_version is not None
                assert beta.protocol_version is not None
                for client in (alpha, beta):
                    listing = await client.list_tools()
                    assert {t.name for t in listing.tools} == {"governed_execute"}
                no_permit = await alpha.call_tool(
                    "governed_execute", {"name": "echo", "arguments": {"text": "unsigned"}}
                )
                assert no_permit.is_error
                spoof = await beta.call_tool("governed_execute", alpha_call)
                assert spoof.is_error
                wrong_tool = await beta.call_tool(
                    "governed_execute",
                    {"name": "echo", "arguments": {"text": "wrong"}, "permit": alpha_permit},
                )
                assert wrong_tool.is_error
                unknown = await alpha.call_tool(
                    "governed_execute", {"name": "halt", "arguments": {}}
                )
                assert unknown.is_error
                assert "Tool not available" in _result(unknown)["error"]

                approved_alpha = await alpha.call_tool("governed_execute", alpha_call)
                assert not approved_alpha.is_error
                assert _result(approved_alpha)["result"] == "hello"
                approved_beta = await beta.call_tool("governed_execute", beta_call)
                assert not approved_beta.is_error
                assert _result(approved_beta)["result"] == 5
                replay = await alpha.call_tool("governed_execute", alpha_call)
                assert replay.is_error
                assert _result(replay)["decision"] == "DENY"

    proc = _start_service(signed_policy, base)
    try:
        asyncio.run(first_session())
    finally:
        _stop(proc)

    # New operator interpreter: permit consumption was in SQLite, not in
    # the short-lived MCP clients or their separate local relay processes.
    async def second_session():
        async with Client(_client(config["port"], token_alpha)) as alpha:
            async with Client(_client(config["port"], token_beta)) as beta:
                for client, data in ((alpha, alpha_call), (beta, beta_call)):
                    response = await client.call_tool("governed_execute", data)
                    assert response.is_error
                    assert _result(response)["decision"] == "DENY"
                wrong = await alpha.call_tool("governed_execute", beta_call)
                assert wrong.is_error

    restarted = _start_service(signed_policy, base)
    try:
        asyncio.run(second_session())
    finally:
        _stop(restarted)


@pytest.mark.parametrize("invalid_port", [0, 65536, True, -1, "8765"])
def test_mcp_relay_refuses_untrusted_or_invalid_destination(invalid_port):
    with pytest.raises(ValueError, match="port"):
        create_local_mcp_agent_relay(
            port=invalid_port, agent_token="agent-alpha." + secrets.token_urlsafe(48)
        )


@pytest.mark.parametrize("invalid_token", [
    "", "no-label", "agent-alpha." + "x" * 20,
    "bad actor." + "x" * 48, "agent-alpha.bad." + "x" * 48,
])
def test_mcp_relay_refuses_invalid_agent_credential(invalid_token):
    with pytest.raises(ValueError, match="credential"):
        _actor_from_token(invalid_token)


def test_relay_refuses_non_operator_tool_and_unavailable_operator_without_leaking_token():
    token = "agent-alpha." + secrets.token_urlsafe(48)
    result = _invoke_local_operator(
        port=1, bearer=token, actor="agent-alpha",
        name="halt", arguments={}, permit=None,
    )
    assert result.is_error
    assert "Tool not available" in _result(result)["error"]
    failure = _invoke_local_operator(
        port=1, bearer=token, actor="agent-alpha",
        name="echo", arguments={"text": "test"}, permit=None,
    )
    assert failure.is_error
    assert "unavailable" in _result(failure)["error"]
    assert token not in failure.content[0].text


def test_relay_does_not_transmit_oversize_or_unserializable_parameters():
    token = "agent-alpha." + secrets.token_urlsafe(48)
    for params in ({"text": "x" * (64 * 1024 + 1)}, {"text": object()}):
        result = _invoke_local_operator(
            port=1, bearer=token, actor="agent-alpha",
            name="echo", arguments=params, permit=None,
        )
        assert result.is_error
        assert token not in result.content[0].text

@pytest.mark.skipif(os.name != "posix", reason="Operator SQLite audit lock is POSIX-only")
def test_two_mcp_clients_execute_concurrently_with_isolated_authority(tmp_path, monkeypatch):
    """Real stdio clients race independent signed one-shot permits over one operator."""
    config, signed_policy, issuer, token_alpha, token_beta = _fixture(tmp_path, monkeypatch)
    base = "http://127.0.0.1:" + str(config["port"])
    alpha_call = {
        "name": "echo",
        "arguments": {"text": "concurrent-alpha"},
        "permit": _sign_permit(
            issuer, "agent-alpha", "echo", {"text": "concurrent-alpha"}
        ),
    }
    beta_call = {
        "name": "add",
        "arguments": {"a": 11, "b": 31},
        "permit": _sign_permit(issuer, "agent-beta", "add", {"a": 11, "b": 31}),
    }

    async def exercise():
        async with Client(_client(config["port"], token_alpha)) as alpha:
            async with Client(_client(config["port"], token_beta)) as beta:
                # Separate relay processes and independent bearer credentials.
                first_a, first_b = await asyncio.gather(
                    alpha.call_tool("governed_execute", alpha_call),
                    beta.call_tool("governed_execute", beta_call),
                )
                assert not first_a.is_error
                assert not first_b.is_error
                assert _result(first_a)["result"] == "concurrent-alpha"
                assert _result(first_b)["result"] == 42

                # Replay must still be consumed even when the two operations
                # were submitted concurrently through independent relays.
                replay_a, replay_b = await asyncio.gather(
                    alpha.call_tool("governed_execute", alpha_call),
                    beta.call_tool("governed_execute", beta_call),
                )
                for response in (replay_a, replay_b):
                    assert response.is_error
                    assert _result(response)["decision"] == "DENY"

                # Cross-agent signed permits cannot be borrowed.
                borrowed_a, borrowed_b = await asyncio.gather(
                    alpha.call_tool("governed_execute", beta_call),
                    beta.call_tool("governed_execute", alpha_call),
                )
                assert borrowed_a.is_error
                assert borrowed_b.is_error

    proc = _start_service(signed_policy, base)
    try:
        asyncio.run(exercise())
    finally:
        _stop(proc)
