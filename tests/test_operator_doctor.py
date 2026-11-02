"""Regression tests for truthful, secret-redacted operator diagnostics."""

import json
import sys

from shards_kernel.__main__ import main
from shards_kernel.cli.doctor import diagnose, run_doctor


def test_library_preflight_succeeds_without_lying_about_service(capsys):
    result = diagnose("library", environ={})
    assert result["ready"] is True
    assert result["assessment"] == "LIBRARY_CHECKS_PASS"
    assert result["scope"].startswith("Preflight")
    assert run_doctor("library", json_output=True) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["profile"] == "library"
    assert parsed["ready"] is True


def test_service_preflight_fails_loudly_with_missing_credentials(capsys, monkeypatch):
    monkeypatch.delenv("SHARDS_KERNEL_API_KEY", raising=False)
    assert run_doctor("service", json_output=True) == 2
    value = json.loads(capsys.readouterr().out)
    assert value["profile"] == "service"
    assert value["ready"] is False
    checks = {x["id"]: x for x in value["checks"]}
    assert checks["http_credential"]["status"] == "BLOCKED"
    assert checks["trusted_issuer"]["status"] == "NOT_VERIFIED"
    assert checks["gateway_security"]["status"] == "NOT_VERIFIED"
    assert checks["durable_evidence"]["status"] == "NOT_VERIFIED"


def test_secret_never_appears_in_any_human_or_json_output(capsys, monkeypatch):
    secret = "super-secret-example-not-for-logs-0123456789"
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", secret)
    for output_json in (False, True):
        assert run_doctor("service", json_output=output_json) == 2
        output = capsys.readouterr().out
        assert secret not in output
        assert "value redacted" in output
        assert "NOT_VERIFIED" in output


def test_invalid_key_never_counted_as_ready():
    result = diagnose("service", environ={"SHARDS_KERNEL_API_KEY": " short "})
    checks = {x["id"]: x for x in result["checks"]}
    assert checks["http_credential"]["status"] == "BLOCKED"
    assert result["ready"] is False


def test_doctor_cli_reports_json_and_status_code(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["shards-kernel", "doctor", "--profile", "library", "--json"])
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["profile"] == "library"
    monkeypatch.setattr(sys, "argv", ["shards-kernel", "doctor", "--profile", "service", "--json"])
    assert main() == 2
    assert json.loads(capsys.readouterr().out)["assessment"] == "NOT_READY"
