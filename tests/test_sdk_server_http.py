"""End-to-end tests for the lightweight SDK HTTP server."""

import json
import urllib.error
import urllib.request

import pytest

from shards_kernel.integrations.wire import boot_strict_kernel
from shards_kernel.sdk.server import KernelServer


@pytest.fixture
def live_server():
    kernel = boot_strict_kernel("sdk-server-test")
    server = KernelServer(kernel, port=0)
    server.start(blocking=False)
    port = server._server.server_address[1]
    try:
        yield server, f"http://127.0.0.1:{port}"
    finally:
        server.stop()


def request_json(url, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
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
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(req, timeout=3)
    assert error.value.code == 500


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

