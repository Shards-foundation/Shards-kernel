"""Regression tests for the Termux Qwen3 governed-agent example.

These run against the real Shards-kernel source in CI.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
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
