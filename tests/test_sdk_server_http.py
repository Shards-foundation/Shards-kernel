"""End-to-end tests for the lightweight SDK HTTP server."""

import json
import urllib.error
import urllib.request

import pytest

from shards_kernel.integrations.wire import boot_strict_kernel
from shards_kernel.sdk.server import KernelServer

TEST_KEY = "shards-test-http-key-32-characters-long-0001"


@pytest.fixture
def live_server():
    kernel = boot_strict_kernel("sdk-server-test")
    server = KernelServer(kernel, port=0, api_key=TEST_KEY, allow_test_clock=True)
    server.start(blocking=False)
    port = server._server.server_address[1]
    try:
        yield server, f"http://127.0.0.1:{port}"
    finally:
        server.stop()


def request_json(url, method="GET", payload=None, token=TEST_KEY):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=3) as response:  # nosec B310: fixed loopback test server URL
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_server_read_routes_and_unknown_route(live_server):
    _server, url = live_server
    assert request_json(url + "/")[1]["kernel_id"] == "sdk-server-test"
    assert request_json(url + "/health")[1]["status"] == "healthy"
    assert request_json(url + "/status")[1]["kernel_id"] == "sdk-server-test"
    assert "ledger_entries" in request_json(url + "/evidence")[1]
    assert "allowed_actors" in request_json(url + "/policy")[1]
    status, payload = request_json(url + "/unknown")
    assert status == 404
    assert payload["error"] == "Not found"


def test_server_submit_reports_missing_fields_and_bad_json(live_server):
    _server, url = live_server
    status, payload = request_json(url + "/submit", "POST", {"actor": "operator"})
    assert status == 400
    assert "Missing field" in payload["error"]

    req = urllib.request.Request(
        url + "/submit",
        data=b"{",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TEST_KEY}"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(req, timeout=3)
    assert error.value.code == 400


def test_server_submit_and_halt(live_server):
    _server, url = live_server
    status, receipt = request_json(
        url + "/submit",
        "POST",
        {
            "request_id": "sdk-1",
            "actor": "unknown-agent",
            "intent": "inspect",
            "tool_call": {"name": "echo", "params": {"text": "x"}},
            "params": {"text": "x"},
        },
    )
    assert status == 200
    assert receipt["decision"] in {"DENY", "HALT"}

    status, result = request_json(url + "/halt", "POST", {})
    assert status == 200
    assert result["status"] == "halted"



def test_all_sensitive_routes_reject_missing_or_invalid_credentials(live_server):
    server, url = live_server
    paths = [
        ("GET", "/status"),
        ("GET", "/evidence"),
        ("GET", "/policy"),
        ("POST", "/submit"),
        ("POST", "/halt"),
    ]
    for method, path in paths:
        for token in (None, "incorrect-token-with-more-than-32-chars"):
            status, payload = request_json(url + path, method, {}, token=token)
            assert status == 401
            assert payload["error"] == "Unauthorized"
    assert server.kernel.get_state().value != "HALTED"


def test_http_server_cannot_start_without_strong_key(monkeypatch):
    monkeypatch.delenv("SHARDS_KERNEL_API_KEY", raising=False)
    kernel = boot_strict_kernel("http-no-auth-test")
    with pytest.raises(ValueError, match="API key"):
        KernelServer(kernel, port=0, allow_test_clock=True)
    with pytest.raises(ValueError, match="API key"):
        KernelServer(kernel, port=0, api_key="short", allow_test_clock=True)
    with pytest.raises(ValueError, match="Remote HTTP binding"):
        KernelServer(kernel, host="0.0.0.0", port=0, api_key=TEST_KEY, allow_test_clock=True)  # nosec B104: test asserts this bind is refused


def test_http_server_no_wildcard_cors(live_server):
    _server, url = live_server
    req = urllib.request.Request(url + "/health", headers={"Origin": "https://attacker.example"})
    with urllib.request.urlopen(req, timeout=3) as response:  # nosec B310: fixed loopback test URL
        assert response.headers.get("Access-Control-Allow-Origin") is None


def test_http_server_rejects_oversized_body_without_executing(live_server):
    import http.client

    server, _url = live_server
    port = server._server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        # Deliberately declare an oversized payload; do not send it. The server
        # must reject Content-Length before reading any request body bytes.
        connection.request(
            "POST",
            "/submit",
            body=b"",
            headers={
                "Content-Length": str(1024 * 1024 + 1),
                "Authorization": f"Bearer {TEST_KEY}",
            },
        )
        response = connection.getresponse()
        assert response.status == 413
        assert json.loads(response.read())["error"] == "Request body too large"
    finally:
        connection.close()
    assert server.kernel.get_state().value != "HALTED"


def test_http_server_no_store_for_authenticated_and_rejected_responses(live_server):
    _server, url = live_server
    for path, token in (("/status", TEST_KEY), ("/status", None), ("/health", None)):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        request = urllib.request.Request(url + path, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=3)  # nosec B310: loopback test
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            assert response.headers["Cache-Control"] == "no-store"


def test_health_reports_unhealthy_after_kernel_halt(live_server):
    server, base = live_server
    status, before = request_json(base + "/health", token=None)
    assert status == 200
    assert before["status"] == "healthy"
    status, _result = request_json(base + "/halt", "POST", {}, token=TEST_KEY)
    assert status == 200
    status, after = request_json(base + "/health", token=None)
    assert status == 503
    assert after == {"status": "unhealthy"}


def test_signed_operator_http_policy_expiry_denies_submit_and_health():
    clocked = boot_strict_kernel("policy-expiry-test")
    clocked.config.clock.set(900)
    server = KernelServer(
        clocked, port=0, api_key=TEST_KEY,
        allow_test_clock=True, policy_expires_at_ms=1000,
    )
    server.start(blocking=False)
    try:
        base = "http://127.0.0.1:" + str(server._server.server_address[1])
        status, health = request_json(base + "/health", token=None)
        assert status == 200
        clocked.config.clock.advance(101)
        status, health = request_json(base + "/health", token=None)
        assert status == 503
        assert health["status"] == "unhealthy"
        status, result = request_json(base + "/submit", "POST", {
            "request_id": "after-expiry",
            "actor": "test-actor",
            "intent": "do not run",
        }, token=TEST_KEY)
        assert status == 503
        assert "expired" in result["error"]
    finally:
        server.stop()
