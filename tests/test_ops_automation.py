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
    raw_health = None
    raw_status = None

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
        override = (self.__class__.raw_health if self.path == "/health"
                    else self.__class__.raw_status)
        data = override if override is not None else json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

@pytest.fixture
def local_operator():
    LocalTestHandler.health = {"status": "healthy", "kernel_state": "IDLE"}
    LocalTestHandler.status = {"state": "IDLE", "kernel_id": "operator-local"}
    LocalTestHandler.failure_count = 0
    LocalTestHandler.requests_seen = []
    LocalTestHandler.redirect = False
    LocalTestHandler.raw_health = None
    LocalTestHandler.raw_status = None
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


@pytest.mark.parametrize("state", [
    "BOOTING", "HALTED", "UNKNOWN", "DEGRADED", "FAILED", "", None, 7,
])
def test_unhealthy_and_unknown_states_never_pass(local_operator, state):
    LocalTestHandler.health = {"status": "healthy", "kernel_state": state}
    with pytest.raises(probe_operator.ProbeFailure, match="unhealthy_kernel"):
        probe_operator.probe_once(config(local_operator), threading.Event())


@pytest.mark.parametrize("state", [
    "IDLE", "VALIDATING", "ARBITRATING", "EXECUTING", "AUDITING", "COMPLETED",
])
def test_authoritative_operational_states_are_accepted(local_operator, state):
    LocalTestHandler.health["kernel_state"] = state
    LocalTestHandler.status["state"] = state
    probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


@pytest.mark.parametrize("state", ["BOOTING", "HALTED", "UNKNOWN", "FAILED", "", None, 123])
def test_invalid_authenticated_states_fail_closed(local_operator, state):
    LocalTestHandler.status["state"] = state
    with pytest.raises(probe_operator.ProbeFailure, match="invalid_kernel_status"):
        probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


@pytest.mark.parametrize("kernel_id", ["", None, 0])
def test_invalid_authenticated_identity_fails_closed(local_operator, kernel_id):
    LocalTestHandler.status["kernel_id"] = kernel_id
    with pytest.raises(probe_operator.ProbeFailure, match="invalid_kernel_status"):
        probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


@pytest.mark.parametrize("bad_key", [
    "a" * 39 + "\t", "a" * 39 + "\x7f", "a" * 39 + "\x00",
    "a" * 19 + " " + "a" * 20, "a" * 39 + "\x1b",
])
def test_control_characters_in_bearer_key_are_rejected(bad_key):
    args = probe_operator.parse_args(["--check-status"])
    with pytest.raises(ValueError, match="SHARDS_KERNEL_API_KEY"):
        probe_operator.validate(args, {"SHARDS_KERNEL_API_KEY": bad_key})


@pytest.mark.parametrize("payload", [
    b"not-json", b"[]", b"null", b"{\"status\":", b"\xff",
])
def test_health_rejects_malformed_json_and_shapes(local_operator, payload):
    LocalTestHandler.raw_health = payload
    with pytest.raises(probe_operator.ProbeFailure, match="invalid_json"):
        probe_operator.probe_once(config(local_operator), threading.Event())


def test_status_rejects_malformed_json(local_operator):
    LocalTestHandler.raw_status = b"{unclosed"
    with pytest.raises(probe_operator.ProbeFailure, match="invalid_json"):
        probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


def test_probe_rejects_oversized_health_and_status(local_operator):
    LocalTestHandler.raw_health = b"x" * (probe_operator.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(probe_operator.ProbeFailure, match="response_too_large"):
        probe_operator.probe_once(config(local_operator), threading.Event())
    LocalTestHandler.raw_health = None
    LocalTestHandler.raw_status = b"y" * (probe_operator.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(probe_operator.ProbeFailure, match="response_too_large"):
        probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


def test_probe_run_fails_on_unknown_state(local_operator):
    LocalTestHandler.health["kernel_state"] = "UNKNOWN"
    assert probe_operator.run(config(local_operator), threading.Event()) == 1


def test_probe_main_signal_exit_codes(local_operator, monkeypatch):
    for number, expected in (
        (probe_operator.signal.SIGINT, 130),
        (probe_operator.signal.SIGTERM, 143),
    ):
        callbacks = {}

        def intercept(signum, handler):
            callbacks[signum] = handler
            return lambda *_args: None

        def interrupt_run(_config, _stop):
            callbacks[number](number, None)
            return 0

        monkeypatch.setattr(probe_operator.signal, "signal", intercept)
        monkeypatch.setattr(probe_operator, "run", interrupt_run)
        assert probe_operator.main(["--url", local_operator]) == expected


def test_probe_does_not_echo_secrets_in_failure_log(local_operator, capsys):
    LocalTestHandler.status = {"state": "FAILED", "kernel_id": "operator-local"}
    result = probe_operator.run(config(local_operator, "--check-status"), threading.Event())
    assert result == 1
    assert "x" * 40 not in capsys.readouterr().out


def test_preflight_rejects_tampered_signed_policy_without_db(tmp_path):
    from shards_kernel.issuer import sign_operator_policy

    now = int(time.time() * 1000)
    signing = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    envelope = sign_operator_policy({
        "version": 1, "kernel_id": "operator-local", "actor": "agent-one",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "operator-key", "issuer": "permit-operator",
            "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"), "port": 8765,
    }, signing, revision=7, issued_at_ms=now - 1000, expires_at_ms=now + 60000)
    path = tmp_path / "signed.json"
    root = signing.public_key().public_bytes_raw().hex()
    opts = dict(policy=path, trusted_key=root, min_ttl_seconds=0,
                minimum_revision=1, expected_kernel_id="operator-local", now_ms=now)
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert policy_preflight.preflight(**opts)["result"] == "SIGNED_POLICY_VALID"

    tampered = json.loads(json.dumps(envelope))
    tampered["revision"] = 8
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError):
        policy_preflight.preflight(**opts)

    tampered = json.loads(json.dumps(envelope))
    tampered["signature_hex"] = "0" * 128
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError):
        policy_preflight.preflight(**opts)

    path.write_text('{"schema":"duplicate","schema":"again"}', encoding="utf-8")
    with pytest.raises(ValueError):
        policy_preflight.preflight(**opts)
    assert not (tmp_path / "audit.sqlite3").exists()


def test_policy_preflight_signal_codes(tmp_path, monkeypatch):
    for signum, expected in (
        (policy_preflight.signal.SIGINT, 130),
        (policy_preflight.signal.SIGTERM, 143),
    ):
        callbacks = {}

        def intercept(number, handler):
            callbacks[number] = handler
            return lambda *_args: None

        def interrupt_preflight(*_args, **_kwargs):
            callbacks[signum](signum, None)
            return {"result": "SIGNED_POLICY_VALID"}

        monkeypatch.setattr(policy_preflight.signal, "signal", intercept)
        monkeypatch.setattr(policy_preflight, "preflight", interrupt_preflight)
        assert policy_preflight.main(["--policy", str(tmp_path / "missing.json")]) == expected


def test_policy_preflight_restores_handlers_on_unexpected_exception(tmp_path, monkeypatch):
    calls = []

    def intercept(signum, _handler):
        calls.append(signum)
        return lambda *_args: None

    def unexpected(*_args, **_kwargs):
        raise RuntimeError("synthetic unexpectedly raised verifier error")

    monkeypatch.setattr(policy_preflight.signal, "signal", intercept)
    monkeypatch.setattr(policy_preflight, "preflight", unexpected)
    assert policy_preflight.main(["--policy", str(tmp_path / "missing.json")]) == 2
    assert calls.count(policy_preflight.signal.SIGINT) == 2
    assert calls.count(policy_preflight.signal.SIGTERM) == 2



@pytest.mark.parametrize("state", [["IDLE"], {"malicious": "object"}, True])
def test_unhashable_health_states_fail_closed(local_operator, state):
    LocalTestHandler.health = {"status": "healthy", "kernel_state": state}
    with pytest.raises(probe_operator.ProbeFailure, match="unhealthy_kernel"):
        probe_operator.probe_once(config(local_operator), threading.Event())


@pytest.mark.parametrize("state", [["IDLE"], {"malicious": "object"}, False])
def test_unhashable_authenticated_states_fail_closed(local_operator, state):
    LocalTestHandler.status["state"] = state
    with pytest.raises(probe_operator.ProbeFailure, match="invalid_kernel_status"):
        probe_operator.probe_once(config(local_operator, "--check-status"), threading.Event())


def test_policy_preflight_missing_trust_root_no_disclosure(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX", raising=False)
    assert policy_preflight.main(["--policy", str(tmp_path / "SENSITIVE-SOURCE.json")]) == 2
    output = capsys.readouterr().out
    assert "SENSITIVE-SOURCE" not in output
    assert "POLICY_REJECTED" in output
