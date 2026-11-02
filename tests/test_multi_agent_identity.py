"""Two independent local agent credentials: no actor or tool impersonation."""

import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.service import build_operator_server, parse_operator_config
from shards_kernel.integrations.auth import AgentIdentity, identify_agent
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PermitBuilder


def _setup(tmp_path):
    issuer = Ed25519PrivateKey.generate()
    alice_token, bob_token = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
    config = {
        "version": 2,
        "kernel_id": "multiagent-kernel",
        "tools": ["echo", "add"],
        "agents": [
            {
                "actor": "agent-alice",
                "token_sha256": hashlib.sha256(alice_token.encode()).hexdigest(),
                "allowed_tools": ["echo"],
            },
            {
                "actor": "agent-bob",
                "token_sha256": hashlib.sha256(bob_token.encode()).hexdigest(),
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
    return config, issuer, alice_token, bob_token


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
    raw, issuer, alice_token, bob_token = _setup(tmp_path)
    config = replace(parse_operator_config(raw), port=0)
    admin = secrets.token_urlsafe(40)
    server = build_operator_server(config, api_key=admin)
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
    "single_agent", "actor_v1_mixed", "unsupported_version",
])
def test_invalid_agent_enrolment_rejected(tmp_path, variant):
    raw, _issuer, _alice, _bob = _setup(tmp_path)
    if variant == "duplicate_actor":
        raw["agents"][1]["actor"] = "agent-alice"
    elif variant == "duplicate_digest":
        raw["agents"][1]["token_sha256"] = raw["agents"][0]["token_sha256"]
    elif variant == "wildcard_actor":
        raw["agents"][0]["actor"] = "*"
    elif variant == "invalid_digest":
        raw["agents"][0]["token_sha256"] = "not-a-digest"
    elif variant == "raw_secret":
        raw["agents"][0]["token"] = "forbidden"
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
    raw, _issuer, alice_token, bob_token = _setup(tmp_path)
    principals = parse_operator_config(raw).agents
    assert identify_agent("Bearer " + alice_token, principals).actor == "agent-alice"
    assert identify_agent("Bearer " + bob_token, principals).actor == "agent-bob"
    for header in (
        "Basic " + alice_token, alice_token, "Bearer " + alice_token + " ",
        "Bearer " + alice_token[:-1], "Bearer ", None,
    ):
        assert identify_agent(header, principals) is None
    assert all(isinstance(p, AgentIdentity) for p in principals)
    assert all(p.token_sha256 not in (alice_token, bob_token) for p in principals)
