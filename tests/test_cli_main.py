"""Tests for the public command-line entry point."""

import json
import sys

import pytest

from shards_kernel import __main__ as cli


@pytest.mark.parametrize("variant", ["strict", "permissive", "evidence-first", "dual-channel"])
def test_info_command_describes_every_supported_variant(monkeypatch, capsys, variant):
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "info", "--variant", variant])
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Variant:" in output
    assert "Fail-Closed: True" in output


def test_no_command_prints_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["shards_kernel"])
    assert cli.main() == 0
    assert "usage:" in capsys.readouterr().out.lower()


def test_validate_command_accepts_valid_request(tmp_path, monkeypatch, capsys):
    request_file = tmp_path / "request.json"
    request_file.write_text(json.dumps({
        "request_id": "r1", "ts_ms": 0, "actor": "operator",
        "intent": "inspect", "params": {}
    }), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "validate", str(request_file)])
    assert cli.main() == 0
    assert "Validation passed." in capsys.readouterr().out


def test_validate_command_reports_missing_file(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "validate", str(missing)])
    assert cli.main() == 1
    assert "File not found" in capsys.readouterr().err


def test_validate_command_reports_invalid_json(tmp_path, monkeypatch, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "validate", str(path)])
    assert cli.main() == 1
    assert "Invalid JSON" in capsys.readouterr().err


def test_validate_command_reports_schema_errors(tmp_path, monkeypatch, capsys):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"request_id": "", "ts_ms": -1}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "validate", str(path)])
    assert cli.main() == 1
    assert "Validation failed:" in capsys.readouterr().out


def test_replay_command_handles_empty_list_and_missing_file(tmp_path, monkeypatch, capsys):
    ledger = tmp_path / "ledger.json"
    ledger.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "replay", str(ledger)])
    assert cli.main() == 0
    assert "Ledger valid." in capsys.readouterr().out

    missing = tmp_path / "missing-ledger.json"
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "replay", str(missing)])
    assert cli.main() == 1
    assert "File not found" in capsys.readouterr().err


def test_replay_command_reports_invalid_json(tmp_path, monkeypatch, capsys):
    ledger = tmp_path / "broken-ledger.json"
    ledger.write_text("{", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["shards_kernel", "replay", str(ledger)])
    assert cli.main() == 1
    assert "Invalid JSON" in capsys.readouterr().err
