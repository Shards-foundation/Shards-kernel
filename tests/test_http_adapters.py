"""HTTP integration tests for the optional Flask and FastAPI adapters."""

import pytest


def test_flask_adapter_exposes_read_endpoints_and_halt():
    pytest.importorskip("flask")
    from kernels.integrations.flask_adapter import create_flask_app

    app = create_flask_app(kernel_id="test-flask")
    client = app.test_client()

    info = client.get("/")
    assert info.status_code == 200
    assert info.get_json()["kernel_id"] == "test-flask"
    assert client.get("/health").get_json()["status"] == "healthy"
    assert client.get("/status").get_json()["kernel_id"] == "test-flask"
    assert "ledger_entries" in client.get("/evidence").get_json()
    assert "allowed_actors" in client.get("/policy").get_json()

    halted = client.post("/halt")
    assert halted.status_code == 200
    assert halted.get_json()["status"] == "halted"


def test_flask_adapter_submit_route_denies_unpermitted_request():
    pytest.importorskip("flask")
    from kernels.integrations.flask_adapter import create_flask_app

    client = create_flask_app(kernel_id="test-flask-submit").test_client()
    response = client.post(
        "/submit",
        json={
            "request_id": "http-1",
            "actor": "unknown-agent",
            "intent": "read status",
            "tool_call": {"name": "echo", "params": {"text": "x"}},
            "params": {"text": "x"},
        },
    )
    assert response.status_code == 200
    assert response.get_json()["decision"] in {"DENY", "HALT"}


def test_fastapi_adapter_exposes_read_endpoints_and_halt():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from kernels.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="test-fastapi")
    with TestClient(app) as client:
        info = client.get("/")
        assert info.status_code == 200
        assert info.json()["kernel_id"] == "test-fastapi"
        assert client.get("/health").json()["status"] == "healthy"
        assert client.get("/status").json()["kernel_id"] == "test-fastapi"
        assert "ledger_entries" in client.get("/evidence").json()
        assert "allowed_actors" in client.get("/policy").json()

        halted = client.post("/halt")
        assert halted.status_code == 200
        assert halted.json()["status"] == "halted"


def test_fastapi_adapter_submit_route_denies_unpermitted_request():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from kernels.integrations.fastapi_adapter import create_fastapi_app

    app = create_fastapi_app(kernel_id="test-fastapi-submit")
    with TestClient(app) as client:
        response = client.post(
            "/submit",
            json={
                "request_id": "http-2",
                "actor": "unknown-agent",
                "intent": "read status",
                "params": {},
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] in {"DENY", "HALT"}
