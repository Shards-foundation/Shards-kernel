"""Regression tests for fail-closed and read-only repository maintenance scripts."""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.maintenance import github_actions_watch as actions
from scripts.maintenance import repo_hygiene as hygiene
from scripts.maintenance import workflow_safety as workflows


def test_hygiene_reports_syntax_and_text_findings(tmp_path: Path) -> None:
    file = tmp_path / "broken.py"
    file.write_bytes(b"def broken(:\r\n  pass \r\n")
    findings = hygiene.file_findings(tmp_path, Path("broken.py"), 2000)
    assert ("critical", "python_syntax_invalid") in findings
    assert ("advisory", "trailing_whitespace") in findings
    assert ("advisory", "crlf_line_endings") in findings


def test_hygiene_detects_conflict_nul_and_missing_file(tmp_path: Path) -> None:
    file = tmp_path / "conflict.txt"
    file.write_text("<<<<<<< ours\nfoo\n=======\nbar\n>>>>>>> theirs\n", encoding="utf-8")
    assert ("critical", "merge_conflict_markers") in hygiene.file_findings(
        tmp_path, Path("conflict.txt"), 2000,
    )
    file.write_bytes(b"abc\x00\n")
    assert ("critical", "nul_byte_in_text") in hygiene.file_findings(
        tmp_path, Path("conflict.txt"), 2000,
    )
    assert ("critical", "tracked_file_missing") in hygiene.file_findings(
        tmp_path, Path("missing.py"), 2000,
    )


def test_hygiene_refuses_unsafe_git_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hygiene, "tracked_paths", lambda _root: [Path("../escape.py")])
    assert hygiene.audit(tmp_path, 2000, False, []) == 2


def test_hygiene_checks_known_files_without_modifying(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "sample.py"
    file.write_text("answer = 42\n", encoding="utf-8")
    initial = file.read_bytes()
    monkeypatch.setattr(hygiene, "tracked_paths", lambda _root: [Path("sample.py")])
    assert hygiene.audit(tmp_path, 2000, True, []) == 0
    assert file.read_bytes() == initial


def test_git_list_is_explicit_argv_not_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    observed = []

    def fake_run(command, **kwargs):
        observed.append((command, kwargs))
        return types.SimpleNamespace(returncode=0, stdout=b"src/a.py\x00README.md\x00")

    monkeypatch.setattr(hygiene.subprocess, "run", fake_run)
    assert hygiene.tracked_paths(tmp_path) == [Path("src/a.py"), Path("README.md")]
    assert observed[0][0] == ["git", "ls-files", "--cached", "-z"]
    assert "shell" not in observed[0][1]


def test_workflow_pinned_action_passes() -> None:
    source = "on:\n  push:\njobs:\n  ci:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n"
    assert workflows.analyse_workflow(source) == []


def test_workflow_unpinned_and_privileged_patterns() -> None:
    source = (
        "on:\n  pull_request_target:\npermissions: write-all\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: curl https://example.com/install.sh | sh\n"
        "      - with:\n          persist-credentials: true\n"
        "          ref: \x24{{ github.event.pull_request.head.sha }}\n"
    )
    found = set(workflows.analyse_workflow(source))
    assert ("advisory", "action_not_full_sha_pinned") in found
    assert ("critical", "workflow_token_write_all") in found
    assert ("critical", "remote_script_piped_to_shell") in found
    assert ("advisory", "checkout_credentials_persisted") in found
    assert ("critical", "privileged_event_checkout_of_pr_head") in found


def test_workflow_audit_is_read_only(tmp_path: Path) -> None:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    path = folder / "ci.yml"
    path.write_text("name: Tests\non: [push]\n", encoding="utf-8")
    original = path.read_bytes()
    assert workflows.audit_workflows(tmp_path, True, []) == 0
    assert path.read_bytes() == original


@pytest.mark.parametrize("repo", [
    "example", "example/../repo", "example/repo/other",
    "example/evil?token=x", "example/%2e%2e",
])
def test_actions_rejects_invalid_repo(repo: str) -> None:
    args = actions.parse_args(["--repo", repo])
    with pytest.raises(actions.MonitorError):
        actions.validate(args)


def test_actions_classifies_stale_and_failed() -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    old = (now - timedelta(hours=4)).isoformat()
    recent = (now - timedelta(minutes=5)).isoformat()
    assert actions.classify(
        {"created_at": old, "status": "in_progress", "conclusion": None}, now, 180,
    ) == "stale"
    assert actions.classify(
        {"created_at": recent, "status": "in_progress", "conclusion": None}, now, 180,
    ) == "pending"
    assert actions.classify(
        {"created_at": recent, "status": "completed", "conclusion": "failure"}, now, 180,
    ) == "failed"
    assert actions.classify(
        {"created_at": recent, "status": "completed", "conclusion": "success"}, now, 180,
    ) == "success"


def test_actions_collector_stops_at_old_page(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    old = (now - timedelta(days=3)).isoformat()
    recent = (now - timedelta(hours=1)).isoformat()
    pages = []

    def fake_fetch(_options, page, _token, _interrupted):
        pages.append(page)
        return {"workflow_runs": [
            {"id": 1, "created_at": recent},
            {"id": 2, "created_at": old},
        ]}

    monkeypatch.setattr(actions, "fetch_page", fake_fetch)
    options = actions.validate(actions.parse_args([]))
    runs, complete, number = actions.collect_runs(options, None, now, [])
    assert [run["id"] for run in runs] == [1]
    assert complete and number == 1
    assert pages == [1]


def test_actions_monitor_refuses_incomplete_results(monkeypatch: pytest.MonkeyPatch) -> None:
    options = actions.validate(actions.parse_args([]))
    monkeypatch.setattr(actions, "collect_runs",
                        lambda *_args: ([], False, 10))
    assert actions.monitor(options, None, []) == 2


def test_actions_monitor_rejects_empty_window(monkeypatch: pytest.MonkeyPatch) -> None:
    options = actions.validate(actions.parse_args([]))
    monkeypatch.setattr(actions, "collect_runs", lambda *_args: ([], True, 1))
    assert actions.monitor(options, None, []) == 2


def test_actions_monitor_reports_failed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    run = {"id": 42, "name": "release", "status": "completed",
           "conclusion": "failure", "created_at": now.isoformat()}
    options = actions.validate(actions.parse_args([]))
    monkeypatch.setattr(actions, "collect_runs",
                        lambda *_args: ([run], True, 1))
    assert actions.monitor(options, None, [], now) == 1


def test_actions_dry_run_never_fetches(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_fetch(*_args, **_kwargs):
        pytest.fail("Dry run attempted network access")

    monkeypatch.setattr(actions, "fetch_page", fail_fetch)
    assert actions.main(["--dry-run"]) == 0


def test_invalid_actions_timestamp_fails_closed() -> None:
    with pytest.raises(actions.MonitorError, match="run_timestamp"):
        actions.parse_timestamp("not-a-date")


def test_json_log_output_does_not_echo_token(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "SENSITIVE_TOKEN_SHOULD_NOT_APPEAR")
    assert actions.main(["--dry-run"]) == 0
    assert "SENSITIVE_TOKEN_SHOULD_NOT_APPEAR" not in capsys.readouterr().out
