"""Verifier-only Termux Phase 3 tool and Qwen proposal tests, no issuer imports."""
from __future__ import annotations

import importlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import sqlite3
import threading

import pytest

PHASE3 = Path(__file__).resolve().parents[1] / "examples" / "termux_phase3"


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.syspath_prepend(str(PHASE3))
    importlib.invalidate_caches()
    return importlib.import_module("agent_tools")


def test_verifier_tool_module_has_no_signing_authority(tools):
    assert not hasattr(tools, "issue")
    assert not hasattr(tools, "sign_v2_permit")
    assert not hasattr(tools, "Ed25519PrivateKey")


def test_strict_qwen_proposals_and_invalid_tools(tools):
    assert tools.parse_plan('{"actions":[{"tool":"add","params":{"a":17,"b":25}}]}') == [
        ("add", {"a": 17, "b": 25})
    ]
    for raw in (
        '{"actions":[{"tool":"shell","params":{"command":"pwd"}}]}',
        '{"actions":[{"tool":"add","params":{"a":true,"b":2}}]}',
        '{"actions":[],"extra":"ignored"}',
        '{"actions":[{"tool":"echo","params":{"text":"x"}}]}' * 4,
    ):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            tools.parse_plan(raw)


def test_note_read_rejects_symlink_fifo_and_oversized_files(tools, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "hello.md").write_text("hello", encoding="utf-8")
    (workspace / "oversize.md").write_bytes(b"a" * 8193)
    (workspace / "link.md").symlink_to(workspace / "hello.md")
    os.mkfifo(workspace / "pipe.md")
    assert tools.safe_read_note(workspace, "hello.md") == "hello"
    assert tools.list_notes(workspace) == ["hello.md", "oversize.md"]
    with pytest.raises(ValueError):
        tools.safe_read_note(workspace, "oversize.md")
    with pytest.raises(OSError):
        tools.safe_read_note(workspace, "link.md")

    results = []

    def read_fifo():
        try:
            tools.safe_read_note(workspace, "pipe.md")
        except Exception as exc:
            results.append(exc)

    task = threading.Thread(target=read_fifo, daemon=True)
    task.start()
    task.join(timeout=3)
    assert not task.is_alive(), "Named pipe must not block kernel execution"
    assert len(results) == 1
    assert isinstance(results[0], ValueError)


def test_memory_is_validated_and_regular_database_only(tools, tmp_path):
    database = tmp_path / "audit-v3.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE agent_memory (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ms INTEGER NOT NULL)"
        )
    assert tools.remember(database, "demo", "value") == "saved"
    assert tools.recall(database, "demo") == "value"
    assert tools.recall(database, "missing") is None
    with pytest.raises(ValueError):
        tools.recall(database, "../secret")

    alias = tmp_path / "symlink.sqlite3"
    alias.symlink_to(database)
    with pytest.raises(ValueError, match="regular file"):
        tools.remember(alias, "demo", "bad")
    assert tools.recall(database, "demo") == "value"


def test_model_client_accepts_only_local_json_tool_proposals(tools, monkeypatch):
    calls = []

    def fake_open(path, *, body=None, timeout=10):
        calls.append(path)
        if path == "/v1/models":
            return {"data": [{"id": "qwen3-local"}]}
        assert json.loads(body)["model"] == "qwen3-local"
        return {
            "choices": [{"message": {"content": '{"actions":[{"tool":"echo","params":{"text":"okay"}}]}'}}]
        }

    monkeypatch.setattr(tools, "_open_json", fake_open)
    assert tools.ask_model("Say okay") == [("echo", {"text": "okay"})]
    assert calls == ["/v1/models", "/v1/chat/completions"]


@pytest.mark.parametrize(
    "models,completion",
    [
        ({"data": []}, None),
        ({"data": [{"id": "local"}]}, {"choices": []}),
        ({"data": [{"id": "local"}]}, {"choices": [{"message": {}}]}),
    ],
)
def test_empty_model_responses_fail_closed(tools, monkeypatch, models, completion):
    def fake_open(path, *, body=None, timeout=10):
        return models if path == "/v1/models" else completion

    monkeypatch.setattr(tools, "_open_json", fake_open)
    with pytest.raises(ValueError, match="MODEL_"):
        tools.ask_model("hello")


def test_model_http_proxy_redirect_and_endpoint_guards(tools, monkeypatch):
    with pytest.raises(ValueError, match="REDIRECT_DENIED"):
        tools._RejectRedirect().redirect_request(
            None, None, 302, "Found", {}, "https://external.example/"
        )
    with pytest.raises(ValueError, match="ENDPOINT_NOT_ALLOWED"):
        tools._open_json("/not-allowed")

    monkeypatch.setattr(
        tools._LOCAL_OPENER,
        "open",
        lambda request, timeout: io.BytesIO(b"x" * (tools.MAX_MODEL_RESPONSE_BYTES + 1)),
    )
    with pytest.raises(ValueError, match="RESPONSE_TOO_LARGE"):
        tools._open_json("/v1/models")


def test_live_loopback_model_http_and_redirect_denial(tools, monkeypatch):
    """Actually serve OpenAI-compatible JSON on localhost; never follow 302."""
    mode = {"redirect": False, "posts": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return None

        def respond(self, data):
            raw = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != "/v1/models":
                self.send_error(404)
                return
            if mode["redirect"]:
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/forbidden")
                self.end_headers()
                return
            self.respond({"data": [{"id": "qwen-local"}]})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            assert body["model"] == "qwen-local"
            mode["posts"] += 1
            self.respond({
                "choices": [{"message": {
                    "content": '{"actions":[{"tool":"add","params":{"a":17,"b":25}}]}'
                }}]
            })

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    runner = threading.Thread(target=server.serve_forever, daemon=True)
    runner.start()
    try:
        monkeypatch.setattr(tools, "MODEL_HOST", f"http://127.0.0.1:{server.server_port}")
        assert tools.ask_model("Add 17 and 25") == [("add", {"a": 17, "b": 25})]
        assert mode["posts"] == 1
        mode["redirect"] = True
        with pytest.raises(ValueError, match="LOCAL_MODEL_REDIRECT_DENIED"):
            tools.ask_model("Add 17 and 25")
        assert mode["posts"] == 1  # No completion request after redirect.
    finally:
        server.shutdown()
        server.server_close()
        runner.join(timeout=3)
