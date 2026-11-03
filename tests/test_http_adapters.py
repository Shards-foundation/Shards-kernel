"""Authentication and kernel contract tests for optional Flask and FastAPI servers."""

import pytest

TEST_KEY = "shards-test-http-key-32-characters-long-0001"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_KEY}"}
DENIED_REQUEST = {
    "request_id": "http-1",
    "actor": "unknown-agent",
    "intent": "read status",
    "tool_call": {"name": "echo", "params": {"text": "x"}},
    "params": {"text": "x"},
}


def test_flask_adapter_exposes_authenticated_routes_and_halt():
    pytest.importorskip("flask")
    from shards_kernel.integrations.flask_adapter import create_flask_app

    app = create_flask_app(kernel_id="test-flask", api_key=TEST_KEY)
    client = app.test_client()

    assert client.get("/").status_code == 200
    assert client.get("/health").get_json()["status"] == "healthy"
    assert client.get("/status", headers=AUTH_HEADER).get_json()["kernel_id"] == "test-flask"
    assert "ledger_entries" in client.get("/evidence", headers=AUTH_HEADER).get_json()
    assert "allowed_actors" in client.get("/policy", headers=AUTH_HEADER).get_json()

    receipt = client.post("/submit", json=DENIED_REQUEST, headers=AUTH_HEADER)
    assert receipt.status_code == 200
    assert receipt.get_json()["decision"] in {"DENY", "HALT"}

    halted = client.post("/halt", headers=AUTH_HEADER)
    assert halted.status_code == 200
    assert halted.get_json()["status"] == "halted"


def test_flask_adapter_rejects_anonymous_control_and_audit_access():
    pytest.importorskip("flask")
    from shards_kernel.integrations.flask_adapter import create_flask_app

    app = create_flask_app(kernel_id="test-flask-auth", api_key=TEST_KEY)
    client = app.test_client()
    for path in ("/status", "/policy", "/evidence"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/submit", json=DENIED_REQUEST).status_code == 401
    assert client.post("/halt").status_code == 401
    assert client.get("/health").get_json()["kernel_state"] != "HALTED"
    assert client.get("/status", headers=AUTH_HEADER).headers["Cache-Control"] == "no-store"


def test_flask_rejects_malformed_params_without_submitting():
    pytest.importorskip("flask")
    from shards_kernel.integrations.flask_adapter import create_flask_app

    app = create_flask_app(kernel_id="test-flask-malformed", api_key=TEST_KEY)
    client = app.test_client()
    payload = {**DENIED_REQUEST, "tool_call": {"name": "echo", "params": ["invalid"]}}
    assert client.post("/submit", json=payload, headers=AUTH_HEADER).status_code == 400
    assert client.get("/evidence", headers=AUTH_HEADER).get_json()["entry_count"] == 0


def test_fastapi_adapter_exposes_authenticated_routes_and_halt():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="test-fastapi", api_key=TEST_KEY)
    with TestClient(app, headers=AUTH_HEADER) as client:
        assert client.get("/").status_code == 200
        assert client.get("/health").json()["status"] == "healthy"
        assert client.get("/status").json()["kernel_id"] == "test-fastapi"
        assert "ledger_entries" in client.get("/evidence").json()
        assert "allowed_actors" in client.get("/policy").json()

        receipt = client.post("/submit", json=DENIED_REQUEST)
        assert receipt.status_code == 200
        assert receipt.json()["decision"] in {"DENY", "HALT"}

        halted = client.post("/halt")
        assert halted.status_code == 200
        assert halted.json()["status"] == "halted"


def test_fastapi_rejects_malformed_permit_without_submitting():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="test-fastapi-malformed", api_key=TEST_KEY)
    with TestClient(app, headers=AUTH_HEADER) as client:
        payload = {**DENIED_REQUEST, "permit": {"issuer": "incomplete"}}
        assert client.post("/submit", json=payload).status_code == 400
        assert client.get("/evidence").json()["entry_count"] == 0


def test_fastapi_adapter_rejects_anonymous_control_and_audit_access():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="test-fastapi-auth", api_key=TEST_KEY)
    with TestClient(app) as client:
        for path in ("/status", "/policy", "/evidence"):
            assert client.get(path).status_code == 401
            assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/submit", json=DENIED_REQUEST).status_code == 401
        assert client.post("/halt").status_code == 401
        assert client.get("/health").json()["kernel_state"] != "HALTED"
        assert client.get("/status", headers=AUTH_HEADER).headers["Cache-Control"] == "no-store"
        assert client.get("/status", headers={"Origin": "https://attacker.example"}).headers.get(
            "access-control-allow-origin"
        ) is None


def test_all_http_app_factories_require_an_api_key(monkeypatch):
    monkeypatch.delenv("SHARDS_KERNEL_API_KEY", raising=False)
    pytest.importorskip("flask")
    pytest.importorskip("fastapi")
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app
    from shards_kernel.integrations.flask_adapter import create_flask_app

    with pytest.raises(ValueError, match="API key"):
        create_flask_app(kernel_id="no-auth-flask")
    with pytest.raises(ValueError, match="API key"):
        create_fastapi_app(kernel_id="no-auth-fastapi")


def test_flask_no_store_headers_are_consistent():
    pytest.importorskip("flask")
    from shards_kernel.integrations.flask_adapter import create_flask_app

    client = create_flask_app(kernel_id="flask-cache-test", api_key=TEST_KEY).test_client()
    for method, path, headers in (
        ("GET", "/health", {}),
        ("GET", "/status", {}),
        ("GET", "/status", AUTH_HEADER),
        ("POST", "/halt", {}),
    ):
        response = client.open(path, method=method, headers=headers)
        assert response.headers["Cache-Control"] == "no-store"


def test_fastapi_no_store_headers_are_consistent():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from shards_kernel.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="fastapi-cache-test", api_key=TEST_KEY)
    with TestClient(app) as client:
        for method, path, headers in (
            ("GET", "/health", {}),
            ("GET", "/status", {}),
            ("GET", "/status", AUTH_HEADER),
            ("POST", "/halt", {}),
        ):
            response = client.request(method, path, headers=headers)
            assert response.headers["Cache-Control"] == "no-store"
