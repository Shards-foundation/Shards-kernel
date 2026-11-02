"""Two independent local agent credentials: no actor or tool impersonation."""

import json
import multiprocessing
import os
import secrets
import socket
import time
import urllib.error
import urllib.request
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.service import build_operator_server, parse_operator_config
from shards_kernel.integrations.auth import AgentIdentity, agent_token_kdf, identify_agent
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_operator_policy, sign_v2_permit
from shards_kernel.permits import PermitBuilder


def _setup(tmp_path):
    issuer = Ed25519PrivateKey.generate()
    alice_token = "agent-alice." + secrets.token_urlsafe(40)
    bob_token = "agent-bob." + secrets.token_urlsafe(40)
    pepper = secrets.token_urlsafe(48)
    config = {
        "version": 2,
        "kernel_id": "multiagent-kernel",
        "tools": ["echo", "add"],
        "agents": [
            {
                "actor": "agent-alice",
                "token_scrypt": agent_token_kdf(alice_token, pepper.encode()),
                "allowed_tools": ["echo"],
            },
            {
                "actor": "agent-bob",
                "token_scrypt": agent_token_kdf(bob_token, pepper.encode()),
                "allowed_tools": ["add"],
            },
        ],
        "issuer_keys": [{
            "key_id": "issuer-key",
            "issuer": "operator",
            "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "multi-audit.sqlite3"),
        "port": 8124,
    }
    return config, issuer, alice_token, bob_token, pepper


def _permit(issuer, actor, action, params):
    now = int(time.time() * 1000)
    return sign_v2_permit(
        (
            PermitBuilder().issuer("operator").subject(actor)
            .jurisdiction("default").action(action).params(params)
            .max_executions(1)
            .valid_from_ms(now - 60_000).valid_until_ms(now + 120_000)
            .proposal_hash("approved-" + actor)
            .build_unsigned_v2(key_id="issuer-key", audience="multiagent-kernel")
        ), issuer,
    )


def _payload(actor, action, params, request_id, permit=None):
    obj = {
        "request_id": request_id,
        "actor": actor,
        "intent": "scoped demo",
        "tool_call": {"name": action, "params": params},
        "params": params,
    }
    if permit is not None:
        obj["permit"] = permit_to_mapping(permit)
    return obj


def _http(base, method="GET", *, token=None, data=None):
    body = None if data is None else json.dumps(data).encode("utf-8")
    req = urllib.request.Request(base, method=method, data=body)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=3) as response:  # nosec B310: fixed loopback test URL
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_two_agents_have_disjoint_credentials_and_scopes_with_replay(tmp_path):
    raw, issuer, alice_token, bob_token, pepper = _setup(tmp_path)
    config = replace(parse_operator_config(raw), port=0)
    admin = secrets.token_urlsafe(40)
    server = build_operator_server(config, api_key=admin, agent_pepper=pepper)
    assert server.trusted_actor is None
    assert len(server.agent_identities) == 2
    assert server.kernel._keyring == {}
    assert server.host == "127.0.0.1"
    assert server.kernel.policy.allowed_actors == frozenset({"agent-alice", "agent-bob"})
    server.start(blocking=False)
    try:
        url = "http://127.0.0.1:" + str(server._server.server_address[1])
        alice = _permit(issuer, "agent-alice", "echo", {"text": "alice-only"})
        bob = _permit(issuer, "agent-bob", "add", {"a": 2, "b": 3})
        denied = _payload("agent-alice", "echo", {"text": "alice-only"}, "unauth", alice)
        for invalid in (None, "wrong", admin):
            status, _ = _http(url + "/submit", "POST", token=invalid, data=denied)
            assert status == 401
        status, wrong_actor = _http(
            url + "/submit", "POST", token=bob_token, data=denied
        )
        assert status == 403
        assert wrong_actor["error"] == "Caller identity does not match service principal"
        status, wrong_tool = _http(
            url + "/submit", "POST", token=bob_token,
            data=_payload("agent-bob", "echo", {"text": "bad"}, "scope-denied", alice),
        )
        assert status == 403
        assert wrong_tool["error"] == "Tool not authorised for agent principal"

        status, no_permit = _http(
            url + "/submit", "POST", token=alice_token,
            data=_payload("agent-alice", "echo", {"text": "alice-only"}, "missing"),
        )
        assert status == 200 and no_permit["decision"] == "DENY"

        status, allowed_alice = _http(
            url + "/submit", "POST", token=alice_token,
            data=_payload("agent-alice", "echo", {"text": "alice-only"}, "alice-ok", alice),
        )
        assert status == 200 and allowed_alice["decision"] == "ALLOW"
        assert allowed_alice["result"] == "alice-only"
        status, allowed_bob = _http(
            url + "/submit", "POST", token=bob_token,
            data=_payload("agent-bob", "add", {"a": 2, "b": 3}, "bob-ok", bob),
        )
        assert status == 200 and allowed_bob["decision"] == "ALLOW"
        assert allowed_bob["result"] == 5
        status, cross_permit = _http(
            url + "/submit", "POST", token=bob_token,
            data=_payload("agent-bob", "add", {"a": 2, "b": 3}, "cross", alice),
        )
        assert status == 200 and cross_permit["decision"] == "DENY"
        status, replay = _http(
            url + "/submit", "POST", token=alice_token,
            data=_payload("agent-alice", "echo", {"text": "alice-only"}, "replay", alice),
        )
        assert status == 200 and replay["decision"] == "DENY"
        assert "REPLAY_DETECTED" in replay["error"]

        for path, method in (("/policy", "GET"), ("/evidence", "GET"), ("/halt", "POST")):
            status, _ = _http(url + path, method, token=alice_token, data={} if method == "POST" else None)
            assert status == 401
        assert _http(url + "/status", token=admin)[0] == 200
        assert _http(url + "/evidence", token=admin)[0] == 200
    finally:
        server.stop()


@pytest.mark.parametrize("variant", [
    "duplicate_actor", "duplicate_digest", "wildcard_actor",
    "invalid_digest", "raw_secret", "unknown_tool", "duplicate_tool",
    "single_agent", "actor_v1_mixed", "unsupported_version", "dot_actor",
])
def test_invalid_agent_enrolment_rejected(tmp_path, variant):
    raw, _issuer, _alice, _bob, _pepper = _setup(tmp_path)
    if variant == "duplicate_actor":
        raw["agents"][1]["actor"] = "agent-alice"
    elif variant == "duplicate_digest":
        raw["agents"][1]["token_scrypt"] = raw["agents"][0]["token_scrypt"]
    elif variant == "wildcard_actor":
        raw["agents"][0]["actor"] = "*"
    elif variant == "dot_actor":
        raw["agents"][0]["actor"] = "agent.alpha"
    elif variant == "invalid_digest":
        raw["agents"][0]["token_scrypt"] = secrets.token_urlsafe(4)
    elif variant == "raw_secret":
        raw["agents"][0]["token"] = secrets.token_urlsafe(48)
    elif variant == "unknown_tool":
        raw["agents"][0]["allowed_tools"] = ["echo", "shell"]
    elif variant == "duplicate_tool":
        raw["agents"][0]["allowed_tools"] = ["echo", "echo"]
    elif variant == "single_agent":
        raw["agents"] = raw["agents"][:1]
    elif variant == "actor_v1_mixed":
        raw["actor"] = "agent-alice"
    elif variant == "unsupported_version":
        raw["version"] = 3
    with pytest.raises(ValueError):
        parse_operator_config(raw)


def test_principal_resolution_does_not_accept_tokens_with_whitespace_or_truncation(tmp_path):
    raw, _issuer, alice_token, bob_token, pepper = _setup(tmp_path)
    principals = parse_operator_config(raw).agents
    assert identify_agent("Bearer " + alice_token, principals, pepper.encode()).actor == "agent-alice"
    assert identify_agent("Bearer " + bob_token, principals, pepper.encode()).actor == "agent-bob"
    for header in (
        "Basic " + alice_token, alice_token, "Bearer " + alice_token + " ",
        "Bearer " + alice_token[:-1], "Bearer ", None,
    ):
        assert identify_agent(header, principals, pepper.encode()) is None
    assert all(isinstance(p, AgentIdentity) for p in principals)
    assert all(p.token_scrypt not in (alice_token, bob_token) for p in principals)


def test_operator_and_agent_secret_collision_is_rejected(tmp_path):
    raw, _issuer, alice_token, _bob_token, pepper = _setup(tmp_path)
    with pytest.raises(ValueError, match="credentials must not be shared"):
        build_operator_server(parse_operator_config(raw), api_key=alice_token, agent_pepper=pepper)


def test_missing_authentication_mac_key_refuses_multi_agent_startup(tmp_path, monkeypatch):
    raw, _issuer, _alice, _bob, _pepper = _setup(tmp_path)
    monkeypatch.delenv("SHARDS_KERNEL_AGENT_AUTH_PEPPER", raising=False)
    with pytest.raises(ValueError, match="pepper"):
        build_operator_server(
            parse_operator_config(raw), api_key=secrets.token_urlsafe(40)
        )


def test_wrong_authentication_mac_key_cannot_authenticate_any_agent(tmp_path):
    raw, _issuer, alice, bob, _correct_pepper = _setup(tmp_path)
    server = build_operator_server(
        replace(parse_operator_config(raw), port=0),
        api_key=secrets.token_urlsafe(40),
        agent_pepper=secrets.token_urlsafe(48),
    )
    server.start(blocking=False)
    try:
        base = "http://127.0.0.1:" + str(server._server.server_address[1])
        for token in (alice, bob):
            status, _ = _http(
                base + "/submit", "POST", token=token,
                data=_payload("agent-alice", "echo", {"text": "no"}, "wrong-pepper"),
            )
            assert status == 401
    finally:
        server.stop()


def _operator_process(config_file):
    import sys

    from shards_kernel.__main__ import main

    sys.argv = ["shards-kernel", "serve", "--config", str(config_file)]
    raise SystemExit(main())


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_signed_service(config_file, url):
    process = multiprocessing.get_context("spawn").Process(
        target=_operator_process, args=(str(config_file),)
    )
    process.start()
    for _ in range(100):
        if not process.is_alive():
            raise AssertionError("Signed v2 operator did not start")
        try:
            status, health = _http(url + "/health")
            if status == 200 and health["status"] == "healthy":
                return process
        except OSError:
            pass
        time.sleep(0.1)
    _kill(process)
    raise AssertionError("Signed v2 operator was not healthy")


def _kill(process):
    if process.is_alive():
        process.terminate()
    process.join(timeout=8)
    if process.is_alive():
        process.kill()
        process.join(timeout=8)
    assert not process.is_alive()


@pytest.mark.skipif(os.name != "posix", reason="Operator uses POSIX single-writer lock")
def test_signed_two_agent_cli_survives_restart_and_preserves_separation(
    tmp_path, monkeypatch
):
    raw, permit_issuer, alice_token, bob_token, pepper = _setup(tmp_path)
    raw["port"] = _free_loopback_port()
    policy_issuer = Ed25519PrivateKey.generate()
    now = int(time.time() * 1000)
    signed = sign_operator_policy(
        raw, policy_issuer, revision=1,
        issued_at_ms=now - 20_000, expires_at_ms=now + 600_000,
    )
    path = tmp_path / "two-agent-policy.json"
    path.write_text(json.dumps(signed))
    operator_secret = secrets.token_urlsafe(40)
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", operator_secret)
    monkeypatch.setenv("SHARDS_KERNEL_AGENT_AUTH_PEPPER", pepper)
    monkeypatch.setenv(
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
        policy_issuer.public_key().public_bytes_raw().hex(),
    )
    base = "http://127.0.0.1:" + str(raw["port"])
    permit_a = _permit(permit_issuer, "agent-alice", "echo", {"text": "alice-only"})
    permit_b = _permit(permit_issuer, "agent-bob", "add", {"a": 2, "b": 3})
    first = _start_signed_service(path, base)
    try:
        status, receipt_a = _http(
            base + "/submit", "POST", token=alice_token,
            data=_payload("agent-alice", "echo", {"text": "alice-only"}, "a1", permit_a),
        )
        assert status == 200 and receipt_a["decision"] == "ALLOW"
        status, receipt_b = _http(
            base + "/submit", "POST", token=bob_token,
            data=_payload("agent-bob", "add", {"a": 2, "b": 3}, "b1", permit_b),
        )
        assert status == 200 and receipt_b["decision"] == "ALLOW"
        assert receipt_b["result"] == 5
        status, evidence = _http(base + "/evidence", token=operator_secret)
        assert status == 200 and evidence["entry_count"] >= 4
        status, _ = _http(base + "/evidence", token=alice_token)
        assert status == 401
    finally:
        _kill(first)

    second = _start_signed_service(path, base)
    try:
        status, recovered = _http(base + "/evidence", token=operator_secret)
        assert status == 200 and recovered["root_hash"] == evidence["root_hash"]
        for actor, action, params, permit, token in (
            ("agent-alice", "echo", {"text": "alice-only"}, permit_a, alice_token),
            ("agent-bob", "add", {"a": 2, "b": 3}, permit_b, bob_token),
        ):
            status, denied = _http(
                base + "/submit", "POST", token=token,
                data=_payload(actor, action, params, "replay-" + actor, permit),
            )
            assert status == 200 and denied["decision"] == "DENY"
            assert "REPLAY_DETECTED" in denied["error"]
        status, _ = _http(
            base + "/submit", "POST", token=bob_token,
            data=_payload("agent-alice", "echo", {"text": "alice-only"}, "spoof", permit_a),
        )
        assert status == 403
    finally:
        _kill(second)
