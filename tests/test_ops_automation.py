"""Read-only operator automation negative-path tests."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.ops import policy_preflight, probe_operator


class LocalTestHandler(BaseHTTPRequestHandler):
    health = {"status": "healthy", "kernel_state": "IDLE"}
    status = {"state": "IDLE", "kernel_id": "operator-local"}
    failure_count = 0
    requests_seen = []
    redirect = False

    def do_GET(self):
        self.__class__.requests_seen.append((self.path, self.headers.get("Authorization")))
        if self.__class__.redirect:
            self.send_response(302)
            self.send_header("Location", "https://example.com/steal")
            self.end_headers()
            return
        if self.path == "/health" and self.__class__.failure_count > 0:
            self.__class__.failure_count -= 1
            self.send_response(503)
            self.end_headers()
            return
        response = self.__class__.health if self.path == "/health" else self.__class__.status
        data = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


@pytest.fixture
def local_operator():
    LocalTestHandler.health = {"status": "healthy", "kernel_state": "IDLE"}
    LocalTestHandler.status = {"state": "IDLE", "kernel_id": "operator-local"}
    LocalTestHandler.failure_count = 0
    LocalTestHandler.requests_seen = []
    LocalTestHandler.redirect = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalTestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def config(url, *extra):
    args = probe_operator.parse_args(["--url", url, *extra])
    return probe_operator.validate(args, {"SHARDS_KERNEL_API_KEY": "x" * 40})


def test_health_and_authenticated_identity(local_operator):
    c = config(local_operator, "--check-status", "--expected-kernel-id", "operator-local")
    probe_operator.probe_once(c, threading.Event())
    assert LocalTestHandler.requests_seen == [
        ("/health", None), ("/status", "Bearer " + "x" * 40)
    ]


def test_no_state_leak_auth_and_invalid_identity_fail(local_operator):
    c = config(local_operator, "--check-status", "--expected-kernel-id", "other")
    with pytest.raises(probe_operator.ProbeFailure, match="wrong_kernel_identity"):
        probe_operator.probe_once(c, threading.Event())
    LocalTestHandler.health = {"status": "healthy"}
    with pytest.raises(probe_operator.ProbeFailure, match="unhealthy_kernel"):
        probe_operator.probe_once(c, threading.Event())


def test_transient_retry_and_no_redirect(local_operator, monkeypatch):
    monkeypatch.setattr(probe_operator, "MAX_BACKOFF_SECONDS", 0.01)
    LocalTestHandler.failure_count = 2
    probe_operator.probe_once(config(local_operator), threading.Event())
    assert len(LocalTestHandler.requests_seen) == 3
    LocalTestHandler.redirect = True
    with pytest.raises(probe_operator.ProbeFailure, match="http_302"):
        probe_operator.probe_once(config(local_operator, "--attempts", "1"), threading.Event())


@pytest.mark.parametrize("url", [
    "https://example.com:443", "http://localhost:8765", "http://127.0.0.1",
    "http://user:password@127.0.0.1:8765", "http://127.0.0.1:8765/submit",
    "file:///etc/passwd", "http://127.0.0.1:8765#attack",
])
def test_no_untrusted_destination(url):
    with pytest.raises(ValueError):
        probe_operator.parse_url(url)


def test_probe_dry_run_no_requests(local_operator):
    c = config(local_operator, "--dry-run")
    assert probe_operator.run(c, threading.Event()) == 0
    assert not LocalTestHandler.requests_seen


def test_policy_validity_and_expiry(tmp_path):
    from shards_kernel.issuer import sign_operator_policy

    now = int(time.time() * 1000)
    key = Ed25519PrivateKey.generate()
    permit_issuer = Ed25519PrivateKey.generate()
    policy = sign_operator_policy({
        "version": 1, "kernel_id": "operator-local", "actor": "agent-one",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "operator-key", "issuer": "permit-operator",
            "public_key_hex": permit_issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"), "port": 8765,
    }, key, revision=7, issued_at_ms=now - 1000, expires_at_ms=now + 60000)
    document = tmp_path / "signed.json"
    document.write_text(json.dumps(policy), encoding="utf-8")
    args = dict(policy=document, trusted_key=key.public_key().public_bytes_raw().hex(),
                min_ttl_seconds=30, minimum_revision=7, expected_kernel_id="operator-local",
                now_ms=now)
    result = policy_preflight.preflight(**args)
    assert result["result"] == "SIGNED_POLICY_VALID"
    assert not (tmp_path / "audit.sqlite3").exists()
    with pytest.raises(ValueError, match="lifetime"):
        policy_preflight.preflight(**{**args, "min_ttl_seconds": 120})
    with pytest.raises(ValueError, match="revision"):
        policy_preflight.preflight(**{**args, "minimum_revision": 8})
    with pytest.raises(ValueError, match="identity"):
        policy_preflight.preflight(**{**args, "expected_kernel_id": "wrong"})
    with pytest.raises(ValueError):
        policy_preflight.preflight(**{**args, "trusted_key": "00" * 32})
    with pytest.raises(ValueError):
        policy_preflight.preflight(**{**args, "now_ms": now + 61000})


def test_missing_policy_no_raw_paths_in_log(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX", "a" * 64)
    missing = tmp_path / "VERY-SENSITIVE-MOUNT" / "missing.json"
    assert policy_preflight.main(["--policy", str(missing)]) == 2
    output = capsys.readouterr().out
    assert "VERY-SENSITIVE-MOUNT" not in output
    assert "policy_rejected" in output
