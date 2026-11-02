"""Full reference chain across separate OS interpreter processes.

Approver and issuer commands run in their own spawned interpreters. The
operator HTTP service runs in a third spawned interpreter. All keys are
ephemeral test fixtures; production KMS/HSM custody is NOT established.
"""

from __future__ import annotations

import io
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping
from shards_kernel.issuer import sign_operator_policy
from shards_kernel.permits import PermitBuilder


class _FakeReviewTerminal(io.StringIO):
    def isatty(self):
        return True


def _private_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _issuer_child(argv, private_pem, operator_confirmation):
    """Child-created FD models an operator-only secret-manager pipe."""
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, private_pem)
    finally:
        os.close(write_fd)
    try:
        if operator_confirmation is not None:
            sys.stdin = _FakeReviewTerminal(operator_confirmation)
        from shards_kernel.__main__ import main

        sys.argv = ["shards-kernel", "issuer"] + argv + ["--key-fd", str(read_fd)]
        raise SystemExit(main())
    finally:
        os.close(read_fd)


def _kernel_child(path):
    from shards_kernel.__main__ import main

    sys.argv = ["shards-kernel", "serve", "--config", str(path)]
    raise SystemExit(main())


def _child_process(target, *args):
    ctx = multiprocessing.get_context("spawn")
    process = ctx.Process(target=target, args=args)
    process.start()
    return process


def _await_exit(proc, expected=0):
    proc.join(timeout=15)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=5)
    assert not proc.is_alive(), "Child process did not terminate"
    assert proc.exitcode == expected


def _stop_service(proc):
    if proc.is_alive():
        proc.terminate()
    proc.join(timeout=10)
    if proc.is_alive():
        proc.kill()
        proc.join(timeout=10)
    assert not proc.is_alive()


def _port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _http(url, *, method="GET", bearer=None, payload=None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if bearer is not None:
        req.add_header("Authorization", "Bearer " + bearer)
    try:
        with urllib.request.urlopen(req, timeout=2) as res:  # nosec B310: loopback test only
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _start_service(path, base):
    proc = _child_process(_kernel_child, str(path))
    for _ in range(100):
        if not proc.is_alive():
            _stop_service(proc)
            raise AssertionError("Signed operator service exited before accepting requests")
        try:
            code, response = _http(base + "/health")
            if code == 200 and response.get("status") == "healthy":
                return proc
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    _stop_service(proc)
    raise AssertionError("Signed operator service did not become healthy")


@pytest.mark.skipif(os.name != "posix", reason="Local operator service uses POSIX advisory locks")
def test_separate_approver_issuer_and_kernel_processes(tmp_path, monkeypatch):
    approver_key = Ed25519PrivateKey.generate()
    issuer_key = Ed25519PrivateKey.generate()
    policy_key = Ed25519PrivateKey.generate()
    now = int(time.time() * 1000)
    unsigned = (
        PermitBuilder()
        .issuer("offline-issuer")
        .subject("agent-one")
        .jurisdiction("default")
        .action("echo")
        .params({"text": "approved-once"})
        .max_executions(1)
        .valid_from_ms(now - 10_000)
        .valid_until_ms(now + 8 * 60_000)
        .proposal_hash("operator-reviewed-proposal")
        .build_unsigned_v2(key_id="issuer-key-1", audience="kernel-three-process")
    )
    draft_file = tmp_path / "unsigned.json"
    draft_file.write_text(json.dumps(permit_to_mapping(unsigned)))
    approval_file = tmp_path / "approval.json"
    permit_file = tmp_path / "permit.json"

    issuer_args = [
        "sign", "--draft", str(draft_file), "--approval", str(approval_file),
        "--out", str(permit_file), "--approver-public-key-hex",
        approver_key.public_key().public_bytes_raw().hex(),
        "--expected-issuer", "offline-issuer", "--expected-key-id", "issuer-key-1",
    ]

    # A signing-capable issuer may not mint anything before independent approval.
    no_approval = _child_process(
        _issuer_child, issuer_args, _private_pem(issuer_key), None
    )
    _await_exit(no_approval, expected=2)
    assert not permit_file.exists()

    approve = _child_process(
        _issuer_child,
        [
            "approve", "--draft", str(draft_file), "--out", str(approval_file),
            "--reviewer", "operator-one",
        ],
        _private_pem(approver_key),
        "APPROVE " + unsigned.permit_id + "\n",
    )
    _await_exit(approve)
    assert approval_file.exists()

    issuer = _child_process(
        _issuer_child, issuer_args, _private_pem(issuer_key), None
    )
    _await_exit(issuer)
    signed = permit_from_mapping(json.loads(permit_file.read_text()))
    assert signed.signature and signed.permit_id == unsigned.permit_id

    port = _port()
    service_config = {
        "version": 1,
        "kernel_id": "kernel-three-process",
        "actor": "agent-one",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "issuer-key-1",
            "issuer": "offline-issuer",
            "public_key_hex": issuer_key.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": port,
    }
    policy = sign_operator_policy(
        service_config, policy_key, revision=1,
        issued_at_ms=now - 30_000, expires_at_ms=now + 10 * 60_000,
    )
    config_file = tmp_path / "signed-operator-policy.json"
    config_file.write_text(json.dumps(policy))
    bearer = secrets.token_urlsafe(36)
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", bearer)
    monkeypatch.setenv(
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
        policy_key.public_key().public_bytes_raw().hex(),
    )
    base = "http://127.0.0.1:" + str(port)
    submission = {
        "request_id": "first-execution",
        "actor": "agent-one",
        "intent": "approved test echo",
        "tool_call": {"name": "echo", "params": {"text": "approved-once"}},
        "params": {"text": "approved-once"},
        "permit": permit_to_mapping(signed),
    }
    process = _start_service(config_file, base)
    try:
        status, _ = _http(base + "/submit", method="POST", payload=submission)
        assert status == 401
        status, allowed = _http(
            base + "/submit", method="POST", payload=submission, bearer=bearer
        )
        assert status == 200 and allowed["decision"] == "ALLOW"
        assert allowed["result"] == "approved-once"
        status, evidence = _http(base + "/evidence", bearer=bearer)
        assert status == 200 and evidence["entry_count"] >= 2
    finally:
        _stop_service(process)

    # A newly launched kernel process verifies the recovered audit chain and
    # refuses another use of exactly the same issuer-signed permit.
    restarted = _start_service(config_file, base)
    try:
        status, restored = _http(base + "/evidence", bearer=bearer)
        assert status == 200 and restored["root_hash"] == evidence["root_hash"]
        submission["request_id"] = "replay-after-restart"
        status, replay = _http(
            base + "/submit", method="POST", payload=submission, bearer=bearer
        )
        assert status == 200 and replay["decision"] == "DENY"
        assert "REPLAY_DETECTED" in replay["error"]
    finally:
        _stop_service(restarted)

    assert "private_key" not in config_file.read_text()
    assert "PRIVATE KEY" not in permit_file.read_text()
    assert "PRIVATE KEY" not in approval_file.read_text()
