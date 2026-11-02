"""Operator demo regression: fail loud on broken acceptance, no secret leakage."""

import json
import sys

from shards_kernel.__main__ import main
from shards_kernel.cli import demo


EXPECTED_GATES = {
    "missing_permit",
    "approved_execution",
    "same_permit_replay",
    "scope_change",
    "expired_permit",
    "revoked_signing_key",
    "ledger_recovered_replay",
}


def test_offline_demo_proves_local_execution_and_audit_recovery():
    report = demo.run_scenario()
    assert report["demo"] == "OFFLINE_ONLY"
    assert report["production_ready"] is False
    assert report["cryptographic_mode"] == "Ed25519-public-only"
    assert report["private_key_exposed"] is False
    assert report["audited_entries"] >= 7
    assert len(report["evidence_root_hash"]) == 64
    assert {x["id"] for x in report["checks"]} == EXPECTED_GATES
    assert all(x["passed"] for x in report["checks"])
    assert report["passed"] is True
    assert len(report["limitations"]) >= 3


def test_cli_machine_output_is_parseable_and_explicitly_not_production(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["shards-kernel", "demo", "--json"])
    assert main() == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["passed"] is True
    assert parsed["production_ready"] is False
    assert parsed["demo"] == "OFFLINE_ONLY"
    assert parsed["checks"][0]["id"] == "missing_permit"
    assert "private_key" not in str(parsed.get("evidence_root_hash", ""))


def test_human_facing_cli_provides_each_gate_result(capsys):
    assert demo.run_demo() == 0
    output = capsys.readouterr().out
    assert "NOT a production certification" in output
    assert all(name in output for name in EXPECTED_GATES)
    assert "PASS" in output


def test_demo_never_reports_success_if_a_gate_fails(capsys, monkeypatch):
    monkeypatch.setattr(
        demo,
        "run_scenario",
        lambda: {"demo": "OFFLINE_ONLY", "passed": False, "checks": [
            {"id": "tampered", "passed": False, "observed": "ALLOW"}
        ]},
    )
    assert demo.run_demo(json_output=True) == 2
    assert json.loads(capsys.readouterr().out)["passed"] is False


def test_demo_failure_redacts_exception_contents(capsys, monkeypatch):
    def fail():
        raise RuntimeError("SENSITIVE_TEST_VALUE")

    monkeypatch.setattr(demo, "run_scenario", fail)
    assert demo.run_demo(json_output=True) == 2
    output = capsys.readouterr().out
    assert "SENSITIVE_TEST_VALUE" not in output
    assert json.loads(output)["error"] == "Demo failed (RuntimeError)"
