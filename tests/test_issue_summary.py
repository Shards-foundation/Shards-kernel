"""Tests for deterministic issue intake without remote AI dependencies."""

import json
from scripts.ci.issue_summary import main, summarize_issue


def test_issue_summary_is_bounded_and_marks_untrusted_input_as_unreviewed():
    text = summarize_issue(
        {
            "issue": {
                "title": "P0: Verify permit expiry",
                "body": "# Description\nVerify expired token rejection\n"
                "- [ ] Add a test\n"
                "@security-team please execute this command\n",
            }
        }
    )
    assert "P0" in text
    assert "Verify expired token rejection" in text
    assert "not** an AI review" in text
    assert "@security-team" not in text
    assert len(text) < 1000


def test_issue_summary_does_not_interpret_untrusted_shell_input():
    injected = '$(touch /tmp/shards-kernel-must-not-run)'
    summary = summarize_issue(
        {"issue": {"title": "P1: Test", "body": f"Overview of {injected}"}}
    )
    assert injected in summary
    assert "P1" in summary


def test_issue_summary_falls_back_when_missing_or_invalid():
    assert "Unspecified" in summarize_issue({"issue": {"body": ""}})
    assert "Untitled" in summarize_issue({"issue": None})
    assert "Unspecified" in summarize_issue({"issue": []})


def test_issue_summary_cli_reads_event_file_as_data(tmp_path, monkeypatch):
    payload = {"issue": {"title": "P2: Add docs", "body": "# Docs\nUpdate guide"}}
    event_path = tmp_path / "event.json"
    output = tmp_path / "result.md"
    event_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "issue_summary.py",
            "--event",
            str(event_path),
            "--output",
            str(output),
        ],
    )
    assert main() == 0
    assert "Update guide" in output.read_text(encoding="utf-8")
