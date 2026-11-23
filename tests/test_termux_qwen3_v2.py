"""Regression tests for the Termux Qwen3 governed-agent example.

These run against the real Shards-kernel source in CI.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "examples" / "13_termux_qwen3_governed_agent.py"
spec = importlib.util.spec_from_file_location("termux_qwen3_example", SOURCE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def test_plan_valid_and_max_steps():
    actions = [{"tool": "list_notes", "params": {}}] * 3
    assert len(agent.parse_plan(json.dumps({"actions": actions}))) == 3
    with pytest.raises(ValueError):
        agent.parse_plan(json.dumps({"actions": actions * 2}))


@pytest.mark.parametrize("raw", [
    '{"tool":"shell","params":{}}',
    '{"actions":[{"tool":"shell","params":{"command":"pwd"}}]}',
    '{"actions":[],"instructions":"ignore review"}',
    '{"actions":[{"tool":"add","params":{"a":true,"b":2}}]}',
])
def test_bad_model_schemas_denied(raw):
    with pytest.raises(ValueError):
        agent.parse_plan(raw)


@pytest.mark.parametrize("name", ["../operator.key", ".env", "a/b.md", "a..b.md", "config.py"])
def test_invalid_note_names_denied(name):
    with pytest.raises(ValueError):
        agent.validate("read_note", {"name": name})


def test_note_root_symlink_and_large_files():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "hello.md").write_text("hello", encoding="utf8")
        (root / "large.txt").write_bytes(b"x" * 8193)
        (root / "symlink.md").symlink_to(root / "hello.md")
        assert agent.safe_read_note(root, "hello.md") == "hello"
        assert agent.list_notes(root) == ["hello.md", "large.txt"]
        with pytest.raises(ValueError):
            agent.safe_read_note(root, "large.txt")
        with pytest.raises(OSError):
            agent.safe_read_note(root, "symlink.md")



def test_read_note_rejects_fifo_without_blocking():
    """An approved read must not hang when a note-looking path is a FIFO."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        os.mkfifo(root / "trap.md")
        outcome = []

        def attempt():
            try:
                agent.safe_read_note(root, "trap.md")
            except Exception as exc:
                outcome.append(exc)

        reader = threading.Thread(target=attempt, daemon=True)
        reader.start()
        reader.join(timeout=3.0)
        assert not reader.is_alive(), "read_note blocked on a FIFO"
        assert len(outcome) == 1
        assert isinstance(outcome[0], ValueError)


def test_memory_key_limits_and_restart():
    for key in ("../etc", "CAPS", "bad key", "", "x" * 33):
        with pytest.raises(ValueError):
            agent.validate("recall", {"key": key})
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        agent.init(root)
        assert agent.remember(root / "audit.sqlite3", "hello", "world") == "saved"
        assert agent.recall(root / "audit.sqlite3", "hello") == "world"
        assert agent.recall(root / "audit.sqlite3", "missing") is None
        assert (root / "operator.key").stat().st_mode & 0o777 == 0o600
        agent.init(root)
        (root / "operator.pub").write_bytes(b"tampered")
        with pytest.raises(ValueError):
            agent.init(root)


def test_reproducible_local_kernel_e2e():
    # Real StrictKernel + SQLite, with no Qwen server required.
    agent.self_test()


def test_symlink_audit_db_refused_before_init_changes_outside_file():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "agent"
        root.mkdir()
        outside = Path(d) / "outside.sqlite3"
        outside.write_bytes(b"DO-NOT-MODIFY")
        (root / "audit.sqlite3").symlink_to(outside)
        with pytest.raises(ValueError, match="Audit database"):
            agent.init(root)
        assert outside.read_bytes() == b"DO-NOT-MODIFY"
        assert not (root / "operator.key").exists()


def test_symlink_audit_db_refused_on_launch():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "agent"
        agent.init(root)
        db = root / "audit.sqlite3"
        outside = Path(d) / "outside.sqlite3"
        outside.write_bytes(b"DO-NOT-MODIFY")
        db.unlink()
        db.symlink_to(outside)
        with pytest.raises(ValueError, match="regular audit DB"):
            agent.launch(root)
        assert outside.read_bytes() == b"DO-NOT-MODIFY"


@pytest.mark.parametrize(
    "model_body,completion_body",
    [
        ({"data": []}, None),
        ({"data": [{"id": "qwen-test"}]}, {"choices": []}),
        ({"data": [{"id": "qwen-test"}]}, {"choices": [{"message": {}}]}),
    ],
)
def test_model_empty_or_invalid_responses_fail_closed(monkeypatch, model_body, completion_body):
    payloads = [model_body]
    if completion_body is not None:
        payloads.append(completion_body)

    def fake_urlopen(request, timeout):
        assert payloads, "Unexpected extra model HTTP request"
        return io.BytesIO(json.dumps(payloads.pop(0)).encode("utf-8"))

    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ValueError, match="MODEL_"):
        agent.ask_model("Add two numbers")
