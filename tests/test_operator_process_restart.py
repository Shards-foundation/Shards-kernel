"""Real OS process integration: operator CLI restart must preserve permit consumption.

The trusted issuer key is held only in the test parent. The operator service
runs under the multiprocessing 'spawn' start method in a fresh interpreter.
"""

from __future__ import annotations

import json
import multiprocessing
import secrets
import socket
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_operator_policy, sign_v2_permit
from shards_kernel.permits import PermitBuilder


def _unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _request(url, method="GET", payload=None, bearer=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if bearer is not None:
        request.add_header("Authorization", "Bearer " + bearer)
    try:
        with urllib.request.urlopen(request, timeout=1) as response:  # nosec B310: fixed 127.0.0.1
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _run_cli(config_path, *, allow_unsigned_local=False):
    """Enter through the installed command parser in a fresh interpreter."""
    import sys

    from shards_kernel.__main__ import main

    sys.argv = ["shards-kernel", "serve", "--config", str(config_path)]
    if allow_unsigned_local:
        sys.argv.append("--allow-unsigned-local")
    raise SystemExit(main())


def _launch(config_path, base, *, allow_unsigned_local=False):
    ctx = multiprocessing.get_context("spawn")
    process = ctx.Process(
        target=_run_cli,
        kwargs={"config_path": str(config_path), "allow_unsigned_local": allow_unsigned_local},
    )
    process.start()
    for _ in range(100):
        if not process.is_alive():
            raise AssertionError("Operator service exited before health responded")
        try:
            status, data = _request(base + "/health")
            if status == 200 and data["status"] == "healthy":
                return process
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    _terminate(process)
    raise AssertionError("Operator service never started on loopback")


def _terminate(process):
    if process.is_alive():
        process.terminate()
    process.join(timeout=8)
    if process.is_alive():
        process.kill()
        process.join(timeout=8)
    assert not process.is_alive()


def _permit(signing_key):
    now = int(time.time() * 1000)
    unsigned = (
        PermitBuilder()
        .issuer("trusted-operator")
        .subject("only-local-agent")
        .jurisdiction("default")
        .action("echo")
        .params({"text": "one-time"})
        .valid_from_ms(now - 30_000)
        .valid_until_ms(now + 120_000)
        .proposal_hash("separate-issuer-approved")
        .max_executions(1)
        .build_unsigned_v2(key_id="operator-public", audience="operator-cli-e2e")
    )
    return sign_v2_permit(unsigned, signing_key)


def _payload(request_id, permit, actor="only-local-agent"):
    return {
        "request_id": request_id,
        "actor": actor,
        "intent": "controlled one-time echo",
        "tool_call": {"name": "echo", "params": {"text": "one-time"}},
        "params": {"text": "one-time"},
        "permit": permit_to_mapping(permit),
    }


def test_real_cli_service_process_restart_prevents_ed25519_replay(
    tmp_path, monkeypatch
):
    port = _unused_port()
    private_key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "operator.json"
    config_path.write_text(json.dumps({
        "version": 1,
        "kernel_id": "operator-cli-e2e",
        "actor": "only-local-agent",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "operator-public",
            "issuer": "trusted-operator",
            "public_key_hex": private_key.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "operator.sqlite3"),
        "port": port,
    }))
    bearer = secrets.token_urlsafe(40)
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", bearer)
    base = "http://127.0.0.1:" + str(port)
    permit = _permit(private_key)

    process = _launch(config_path, base, allow_unsigned_local=True)
    try:
        unauthorized, _ = _request(base + "/submit", "POST", _payload("none", permit))
        assert unauthorized == 401
        spoofed, _ = _request(
            base + "/submit",
            "POST",
            _payload("spoof", permit, actor="another-agent"),
            bearer,
        )
        assert spoofed == 403

        accepted, receipt = _request(
            base + "/submit", "POST", _payload("one-allow", permit), bearer
        )
        assert accepted == 200
        assert receipt["decision"] == "ALLOW"
        assert receipt["result"] == "one-time"
        status, evidence = _request(base + "/evidence", bearer=bearer)
        assert status == 200
        assert evidence["entry_count"] >= 2
    finally:
        _terminate(process)

    # Start a *new interpreter*, load verified audit entries from local disk,
    # and assert the already consumed permit cannot execute a second time.
    restarted = _launch(config_path, base, allow_unsigned_local=True)
    try:
        status, restored = _request(base + "/evidence", bearer=bearer)
        assert status == 200
        assert restored["root_hash"] == evidence["root_hash"]
        rejected, receipt = _request(
            base + "/submit", "POST", _payload("after-hard-restart", permit), bearer
        )
        assert rejected == 200
        assert receipt["decision"] == "DENY"
        assert "REPLAY_DETECTED" in receipt["error"]
    finally:
        _terminate(restarted)


def test_signed_operator_config_pinned_key_and_replay_across_real_restart(
    tmp_path, monkeypatch
):
    """Signed policy is verified in actual child process and revision is pinned to DB."""
    port = _unused_port()
    permit_signer = Ed25519PrivateKey.generate()
    policy_signer = Ed25519PrivateKey.generate()
    now = int(time.time() * 1000)
    config = {
        "version": 1,
        "kernel_id": "operator-cli-e2e",
        "actor": "only-local-agent",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "operator-public",
            "issuer": "trusted-operator",
            "public_key_hex": permit_signer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": port,
    }
    signed = sign_operator_policy(
        config, policy_signer, revision=1,
        issued_at_ms=now - 20_000,
        expires_at_ms=now + 300_000,
    )
    config_path = tmp_path / "signed.json"
    config_path.write_text(json.dumps(signed))
    monkeypatch.setenv(
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
        policy_signer.public_key().public_bytes_raw().hex(),
    )
    bearer = secrets.token_urlsafe(40)
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", bearer)
    base = "http://127.0.0.1:" + str(port)
    permit = _permit(permit_signer)

    process = _launch(config_path, base)
    try:
        status, receipt = _request(
            base + "/submit", "POST", _payload("signed-allow", permit), bearer
        )
        assert status == 200
        assert receipt["decision"] == "ALLOW"
        assert receipt["result"] == "one-time"
        status, original = _request(base + "/evidence", bearer=bearer)
        assert status == 200
    finally:
        _terminate(process)

    restarted = _launch(config_path, base)
    try:
        status, restored = _request(base + "/evidence", bearer=bearer)
        assert status == 200
        assert restored["root_hash"] == original["root_hash"]
        status, denied = _request(
            base + "/submit", "POST", _payload("signed-replay", permit), bearer
        )
        assert status == 200
        assert denied["decision"] == "DENY"
        assert "REPLAY_DETECTED" in denied["error"]
    finally:
        _terminate(restarted)

    # A validly signed *older* revision cannot restart this service.
    second = sign_operator_policy(
        config, policy_signer, revision=2,
        issued_at_ms=now - 20_000, expires_at_ms=now + 300_000,
    )
    config_path.write_text(json.dumps(second))
    upgraded = _launch(config_path, base)
    _terminate(upgraded)
    config_path.write_text(json.dumps(signed))
    from shards_kernel.cli.service import run_service

    assert run_service(str(config_path)) == 2
