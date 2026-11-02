"""Operator service end-to-end: config → HTTP → signed permit → durable replay."""

import json
import secrets
import socket
import time
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.service import (
    build_operator_server,
    exclusive_local_audit_lock,
    load_operator_config,
    parse_operator_config,
    run_service,
)
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PermitBuilder


def valid_config(tmp_path, signing_key=None):
    key = signing_key or Ed25519PrivateKey.generate()
    return {
        "version": 1,
        "kernel_id": "operator-local",
        "actor": "signed-local-agent",
        "tools": ["echo"],
        "issuer_keys": [
            {
                "key_id": "trusted-issuer",
                "issuer": "operator",
                "public_key_hex": key.public_key().public_bytes_raw().hex(),
                "revoked": False,
            }
        ],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": 8080,
    }


def send(base, method="GET", payload=None, api_key=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if api_key is not None:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=3) as result:  # nosec B310: local server test
            return result.status, json.loads(result.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def signed_permit(key):
    now = int(time.time() * 1000)
    return sign_v2_permit(
        (
            PermitBuilder()
            .issuer("operator")
            .subject("signed-local-agent")
            .jurisdiction("default")
            .action("echo")
            .params({"text": "approved"})
            .max_executions(1)
            .valid_from_ms(now - 60_000)
            .valid_until_ms(now + 120_000)
            .proposal_hash("operator-approved-in-independent-issuer-test")
            .build_unsigned_v2(key_id="trusted-issuer", audience="operator-local")
        ),
        key,
    )


def submit_body(request_id, permit=None, *, actor="signed-local-agent"):
    body = {
        "request_id": request_id,
        "actor": actor,
        "intent": "repeat scoped text",
        "tool_call": {"name": "echo", "params": {"text": "approved"}},
        "params": {"text": "approved"},
    }
    if permit is not None:
        body["permit"] = permit_to_mapping(permit)
    return body


def test_strict_public_key_config_schema_and_serialisation(tmp_path):
    key = Ed25519PrivateKey.generate()
    data = valid_config(tmp_path, key)
    config = parse_operator_config(data)
    assert config.kernel_id == "operator-local"
    assert config.tools == ("echo",)
    assert config.public_keys["trusted-issuer"].issuer == "operator"
    assert config.public_keys["trusted-issuer"].public_key == key.public_key().public_bytes_raw()
    assert config.audit_db.is_absolute()
    path = tmp_path / "service.json"
    path.write_text(json.dumps(data))
    assert load_operator_config(str(path)) == config
    assert "private" not in json.dumps(data)


@pytest.mark.parametrize(
    "update",
    [
        {"version": 2},
        {"version": True},
        {"actor": "*"},
        {"actor": "an actor"},
        {"tools": ["echo", "echo"]},
        {"tools": ["echo", "arbitrary_tool"]},
        {"tools": ["*"]},
        {"tools": []},
        {"port": 0},
        {"port": True},
        {"port": 65536},
        {"audit_db": "relative-file.sqlite3"},
        {"issuer_keys": []},
    ],
)
def test_invalid_operator_config_fails_closed(tmp_path, update):
    data = valid_config(tmp_path)
    data.update(update)
    with pytest.raises(ValueError):
        parse_operator_config(data)


def test_keys_cannot_be_revoked_all_at_once_and_no_private_fields(tmp_path):
    data = valid_config(tmp_path)
    bad = dict(data)
    bad["issuer_keys"] = [dict(data["issuer_keys"][0], revoked=True)]
    with pytest.raises(ValueError, match="active"):
        parse_operator_config(bad)
    bad = dict(data)
    bad["issuer_keys"] = [dict(data["issuer_keys"][0], private_key="forbidden")]
    with pytest.raises(ValueError, match="Issuer key"):
        parse_operator_config(bad)
    bad = dict(data)
    bad["api_key"] = "forbidden-in-config"
    with pytest.raises(ValueError, match="Operator"):
        parse_operator_config(bad)
    bad = dict(data)
    bad["issuer_keys"] = list(data["issuer_keys"]) * 2
    with pytest.raises(ValueError, match="Duplicate"):
        parse_operator_config(bad)


def test_config_parsing_rejects_duplicates_non_finite_symlinks_and_excess(tmp_path):
    path = tmp_path / "service.json"
    path.write_text('{"version":1,"version":1}')
    with pytest.raises(ValueError, match="Duplicate JSON"):
        load_operator_config(str(path))
    path.write_text('{"version": NaN}')
    with pytest.raises(ValueError, match="Non-finite"):
        load_operator_config(str(path))
    path.write_text("x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="too large"):
        load_operator_config(str(path))
    path.write_text(json.dumps(valid_config(tmp_path)))
    link = tmp_path / "symlink.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="non-symlink"):
        load_operator_config(str(link))
    data = valid_config(tmp_path)
    data["audit_db"] = str(tmp_path / "missing" / "audit.sqlite3")
    with pytest.raises(ValueError, match="parent"):
        parse_operator_config(data)


def test_lock_refuses_concurrent_local_writer(tmp_path):
    path = tmp_path / "audit.sqlite3"
    with exclusive_local_audit_lock(path):
        with pytest.raises(BlockingIOError):
            with exclusive_local_audit_lock(path):
                pytest.fail("Second local writer must never acquire lock")
    with exclusive_local_audit_lock(path):
        pass


def test_missing_http_credential_prevents_build(tmp_path, monkeypatch):
    monkeypatch.delenv("SHARDS_KERNEL_API_KEY", raising=False)
    config = parse_operator_config(valid_config(tmp_path))
    with pytest.raises(ValueError, match="API key"):
        build_operator_server(config)
    with pytest.raises(ValueError, match="API key"):
        build_operator_server(config, api_key="short")


def test_live_http_single_identity_ed25519_and_sqlite_restart(tmp_path):
    signing_key = Ed25519PrivateKey.generate()  # Test issuer, outside kernel.
    api_key = secrets.token_urlsafe(36)
    config = replace(parse_operator_config(valid_config(tmp_path, signing_key)), port=0)
    permit = signed_permit(signing_key)

    with exclusive_local_audit_lock(config.audit_db):
        server = build_operator_server(config, api_key=api_key)
        assert server.host == "127.0.0.1"
        assert server.trusted_actor == "signed-local-agent"
        assert server.kernel._keyring == {}
        assert server.kernel.config.clock.now_ms() > 0
        server.start(blocking=False)
        try:
            base = "http://127.0.0.1:" + str(server._server.server_address[1])
            status, _ = send(base + "/submit", "POST", submit_body("unauth"), None)
            assert status == 401
            status, _ = send(
                base + "/submit", "POST", submit_body("wrong-actor", actor="spoofed"), api_key
            )
            assert status == 403
            status, denied = send(
                base + "/submit", "POST", submit_body("no-permit"), api_key
            )
            assert status == 200
            assert denied["decision"] == "DENY"
            status, allowed = send(
                base + "/submit", "POST", submit_body("approved", permit), api_key
            )
            assert status == 200
            assert allowed["decision"] == "ALLOW"
            assert allowed["result"] == "approved"
            status, duplicate = send(
                base + "/submit", "POST", submit_body("duplicate", permit), api_key
            )
            assert duplicate["decision"] == "DENY"
            assert "REPLAY_DETECTED" in duplicate["error"]
            status, evidence = send(base + "/evidence", "GET", None, api_key)
            assert evidence["entry_count"] >= 4
        finally:
            server.stop()

    # Fresh kernel process equivalent: re-open SQLite and reconstruct nonce use.
    with exclusive_local_audit_lock(config.audit_db):
        restarted = build_operator_server(config, api_key=api_key)
        assert restarted.kernel.export_evidence().root_hash == evidence["root_hash"]
        assert restarted.kernel._keyring == {}
        replay = restarted.kernel.submit(
            __import__("shards_kernel.common.types", fromlist=["KernelRequest"]).KernelRequest(
                request_id="after-restart",
                ts_ms=int(time.time() * 1000),
                actor="signed-local-agent",
                intent="repeat approved text",
                tool_call=__import__("shards_kernel.common.types", fromlist=["ToolCall"]).ToolCall(
                    name="echo", params={"text": "approved"}
                ),
                params={"text": "approved"},
            ),
            permit_token=permit,
        )
        assert replay.decision.value == "DENY"
        assert "REPLAY_DETECTED" in (replay.error or "")


def test_cli_cannot_start_with_invalid_operator_file(tmp_path, capsys):
    file = tmp_path / "bad.json"
    file.write_text("{}")
    assert run_service(str(file)) == 2
    output = capsys.readouterr().out
    assert "refused startup" in output
