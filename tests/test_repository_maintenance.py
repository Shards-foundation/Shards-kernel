"""Regression tests for fail-closed and read-only repository maintenance scripts."""

from __future__ import annotations

import itertools
import logging
import types
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
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


def test_hygiene_rejects_symlinked_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("value = 1\n", encoding="utf-8")
    link = tmp_path / "tracked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Host does not permit symlink creation")
    assert ("critical", "symlinked_tracked_directory") in hygiene.file_findings(
        tmp_path, Path("tracked/secret.py"), 1024,
    )


def test_hygiene_restricts_file_bytes(tmp_path: Path) -> None:
    document = tmp_path / "large.md"
    document.write_bytes(b"A" * 128)
    assert hygiene.file_findings(tmp_path, Path("large.md"), 64) == [
        ("advisory", "file_above_scan_limit")
    ]


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
    assert Path(observed[0][0][0]).is_absolute()
    assert Path(observed[0][0][0]).name.lower().startswith("git")
    assert observed[0][0][1:] == ["ls-files", "--cached", "-z"]
    assert "shell" not in observed[0][1]


def test_hygiene_denies_missing_git_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hygiene.shutil, "which", lambda _name: None)
    with pytest.raises(hygiene.AuditError, match="git_unavailable"):
        hygiene.tracked_paths(tmp_path)


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


def test_actions_unauthorized_fails_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnauthorizedOpener:
        calls = 0

        def open(self, request, timeout):
            self.calls += 1
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    opener = UnauthorizedOpener()
    monkeypatch.setattr(actions.urllib.request, "build_opener", lambda *_args: opener)
    options = actions.validate(actions.parse_args(["--attempts", "3"]))
    with pytest.raises(actions.MonitorError, match="github_http_401"):
        actions.fetch_page(options, 1, "synthetic-test-token", [])
    assert opener.calls == 1


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


class _SyntheticApiResponse:
    """Small synthetic API response, never requiring network access."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


def test_actions_transient_transport_failure_retries_once(monkeypatch: pytest.MonkeyPatch) -> None:
    class FlakyOpener:
        calls = 0

        def open(self, request, timeout):
            self.calls += 1
            if self.calls == 1:
                raise URLError("synthetic transient outage")
            return _SyntheticApiResponse(b'{"workflow_runs":[]}')

    opener = FlakyOpener()
    ticks = itertools.count(0.0, 99.0)
    monkeypatch.setattr(actions.urllib.request, "build_opener", lambda *_args: opener)
    monkeypatch.setattr(actions.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(actions.time, "sleep", lambda _seconds: None)
    options = actions.validate(actions.parse_args(["--attempts", "2"]))
    assert actions.fetch_page(options, 1, None, []) == {"workflow_runs": []}
    assert opener.calls == 2


@pytest.mark.parametrize("body", [b"not-json", b"[]", b'{"workflow_runs":{}}'])
def test_actions_malformed_api_payload_rejected(
    monkeypatch: pytest.MonkeyPatch, body: bytes,
) -> None:
    class StaticOpener:
        def open(self, request, timeout):
            return _SyntheticApiResponse(body)

    monkeypatch.setattr(actions.urllib.request, "build_opener", lambda *_args: StaticOpener())
    options = actions.validate(actions.parse_args(["--attempts", "1"]))
    with pytest.raises(actions.MonitorError):
        actions.fetch_page(options, 1, None, [])


def test_actions_oversized_api_response_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class OversizedOpener:
        def open(self, request, timeout):
            return _SyntheticApiResponse(b"X" * 16)

    monkeypatch.setattr(actions, "MAX_RESPONSE_BYTES", 15)
    monkeypatch.setattr(actions.urllib.request, "build_opener", lambda *_args: OversizedOpener())
    options = actions.validate(actions.parse_args(["--attempts", "1"]))
    with pytest.raises(actions.MonitorError, match="github_response_too_large"):
        actions.fetch_page(options, 1, None, [])


def test_actions_unexpected_response_status_is_not_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnexpectedOpener:
        def open(self, request, timeout):
            return _SyntheticApiResponse(b'{"workflow_runs":[]}', status=418)

    monkeypatch.setattr(actions.urllib.request, "build_opener", lambda *_args: UnexpectedOpener())
    options = actions.validate(actions.parse_args([]))
    with pytest.raises(actions.MonitorError, match="github_unexpected_http_status"):
        actions.fetch_page(options, 1, None, [])


def test_workflow_invalid_encoding_returns_nonzero(tmp_path: Path) -> None:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "ci.yml").write_bytes(b"\xff")
    assert workflows.audit_workflows(tmp_path, False, []) == 2


def test_hygiene_invalid_encoding_is_critical(tmp_path: Path) -> None:
    (tmp_path / "broken.md").write_bytes(b"\xff")
    assert ("critical", "text_not_utf8") in hygiene.file_findings(
        tmp_path, Path("broken.md"), 100,
    )


def test_hygiene_git_subprocess_io_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_run(*_args, **_kwargs):
        raise OSError("synthetic runner failure")

    monkeypatch.setattr(hygiene.subprocess, "run", fail_run)
    with pytest.raises(hygiene.AuditError, match="git_unavailable_or_timed_out"):
        hygiene.tracked_paths(tmp_path)


def test_actions_interruption_is_130(monkeypatch: pytest.MonkeyPatch) -> None:
    callbacks = {}

    def capture(signum, callback):
        callbacks[signum] = callback
        return lambda *_args: None

    def interrupt(_options, _token, _stopped):
        callbacks[actions.signal.SIGINT](actions.signal.SIGINT, None)
        return 0

    monkeypatch.setattr(actions.signal, "signal", capture)
    monkeypatch.setattr(actions, "monitor", interrupt)
    assert actions.main([]) == 130


def test_hygiene_interruption_is_143(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    callbacks = {}

    def capture(signum, callback):
        callbacks[signum] = callback
        return lambda *_args: None

    def interrupt(_root, _max_bytes, _strict, _interrupted):
        callbacks[hygiene.signal.SIGTERM](hygiene.signal.SIGTERM, None)
        return 143

    monkeypatch.setattr(hygiene.signal, "signal", capture)
    monkeypatch.setattr(hygiene, "audit", interrupt)
    assert hygiene.main(["--repo", str(tmp_path)]) == 143


def test_workflow_interruption_is_130(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    callbacks = {}

    def capture(signum, callback):
        callbacks[signum] = callback
        return lambda *_args: None

    def interrupt(_root, _strict, _interrupted):
        callbacks[workflows.signal.SIGINT](workflows.signal.SIGINT, None)
        return 130

    monkeypatch.setattr(workflows.signal, "signal", capture)
    monkeypatch.setattr(workflows, "audit_workflows", interrupt)
    assert workflows.main(["--repo", str(tmp_path)]) == 130


def test_maintenance_workflow_contract_is_read_only() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / ".github" / "workflows" / "repository-maintenance.yml"
    ).read_text(encoding="utf-8")
    assert "workflow_dispatch:" in source
    assert "schedule:" in source
    assert "pull_request:" in source
    assert "permissions:\n  contents: read\n  actions: read" in source
    assert "github-actions-observability:" in source
    assert "maintenance-regression:" in source
    assert "--cov=scripts.maintenance --cov-branch" in source
    assert "--cov-fail-under=90" in source
    assert '"percent_covered"' in source
    assert "name: maintenance-coverage" in source
    assert "tracked-file-hygiene:" in source
    assert "workflow-safety:" in source
    assert "python scripts/maintenance/repo_hygiene.py --repo ." in source
    assert "python scripts/maintenance/workflow_safety.py --repo ." in source
    assert "python scripts/maintenance/github_actions_watch.py" in source
    assert "persist-credentials: false" in source
    assert "shell=True" not in source
    assert "continue-on-error: true" not in source


@pytest.mark.parametrize("flags", [
    ["--attempts", "0"], ["--attempts", "6"],
    ["--max-pages", "0"], ["--timeout", "0"], ["--timeout", "nan"],
    ["--lookback-hours", "0"], ["--stale-minutes", "0"],
    ["--branch", "../unsafe"],
])
def test_actions_bounded_arguments_fail_closed(flags: list[str]) -> None:
    with pytest.raises(actions.MonitorError):
        actions.validate(actions.parse_args(flags))


def test_actions_unknown_statuses_cannot_pass_as_success() -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    recent = (now - timedelta(minutes=2)).isoformat()
    future = (now + timedelta(hours=1)).isoformat()
    assert actions.classify({"created_at": future, "status": "completed",
                             "conclusion": "success"}, now, 20) == "invalid_clock"
    assert actions.classify({"created_at": recent, "status": "mystery",
                             "conclusion": None}, now, 20) == "unknown_status"
    assert actions.classify({"created_at": recent, "status": "completed",
                             "conclusion": None}, now, 20) == "unknown_conclusion"
    assert actions.classify({"created_at": recent, "status": "completed",
                             "conclusion": "cancelled"}, now, 20) == "advisory"


def test_actions_monitor_allows_known_advisory_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    run = {"id": 1, "name": "cancelled", "status": "completed",
           "conclusion": "cancelled", "created_at": now.isoformat()}
    monkeypatch.setattr(actions, "collect_runs", lambda *_args: ([run], True, 1))
    options = actions.validate(actions.parse_args([]))
    assert actions.monitor(options, None, [], now) == 0


def test_actions_invalid_run_collection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 11, 6, tzinfo=timezone.utc)
    monkeypatch.setattr(actions, "fetch_page",
                        lambda *_args: {"workflow_runs": [None]})
    options = actions.validate(actions.parse_args([]))
    with pytest.raises(actions.MonitorError, match="github_run_shape_invalid"):
        actions.collect_runs(options, None, now, [])


def test_workflow_docker_digest_policy() -> None:
    unpinned = workflows.analyse_workflow("steps:\n  - uses: docker://alpine:latest\n")
    assert ("advisory", "docker_image_not_digest_pinned") in unpinned
    pinned = workflows.analyse_workflow(
        "steps:\n  - uses: docker://alpine@sha256:" + "a" * 64 + "\n"
    )
    assert ("advisory", "docker_image_not_digest_pinned") not in pinned


def test_workflow_empty_directory_rejected(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert workflows.audit_workflows(tmp_path, False, []) == 2


def test_workflow_oversized_input_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "build.yml").write_bytes(b"name: Test\n")
    monkeypatch.setattr(workflows, "MAX_WORKFLOW_BYTES", 1)
    assert workflows.audit_workflows(tmp_path, False, []) == 2


def test_workflow_strict_advisory_fails(tmp_path: Path) -> None:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "build.yml").write_text(
        "steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8",
    )
    assert workflows.audit_workflows(tmp_path, False, []) == 0
    assert workflows.audit_workflows(tmp_path, True, []) == 1


def test_workflow_main_rejects_missing_root_and_allows_dry_run(
    tmp_path: Path,
) -> None:
    assert workflows.main(["--repo", str(tmp_path / "missing")]) == 2
    assert workflows.main(["--repo", str(tmp_path), "--dry-run"]) == 0


def test_workflow_audit_honours_preexisting_interrupt(tmp_path: Path) -> None:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "build.yml").write_text("name: Test\n", encoding="utf-8")
    assert workflows.audit_workflows(tmp_path, False, [workflows.signal.SIGINT]) == 130


def test_hygiene_unknown_file_is_not_decoded(tmp_path: Path) -> None:
    (tmp_path / "unreadable.bin").write_bytes(b"\xff\xfe")
    assert hygiene.file_findings(tmp_path, Path("unreadable.bin"), 100) == []


def test_hygiene_symlink_is_reviewed_without_following(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.md"
    target.write_text("content\n", encoding="utf-8")
    link = tmp_path / "linked.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Host does not permit symlink creation")
    assert hygiene.file_findings(tmp_path, Path("linked.md"), 100) == [
        ("advisory", "tracked_symlink_requires_review")
    ]


def test_hygiene_non_regular_tracked_path_rejected(tmp_path: Path) -> None:
    (tmp_path / "directory.py").mkdir()
    assert hygiene.file_findings(tmp_path, Path("directory.py"), 100) == [
        ("critical", "tracked_path_not_regular_file")
    ]


def test_hygiene_git_executable_inside_repo_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    untrusted = tmp_path / "git"
    untrusted.write_bytes(b"not executable")
    monkeypatch.setattr(hygiene.shutil, "which", lambda _name: str(untrusted))
    with pytest.raises(hygiene.AuditError, match="untrusted_git_executable"):
        hygiene.tracked_paths(tmp_path)


def test_hygiene_git_list_rejects_error_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hygiene.subprocess, "run",
                        lambda *_args, **_kwargs: types.SimpleNamespace(
                            returncode=1, stdout=b"",
                        ))
    with pytest.raises(hygiene.AuditError, match="git_ls_files_failed"):
        hygiene.tracked_paths(tmp_path)


def test_hygiene_git_list_rejects_oversized_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hygiene, "MAX_GIT_OUTPUT", 2)
    monkeypatch.setattr(hygiene.subprocess, "run",
                        lambda *_args, **_kwargs: types.SimpleNamespace(
                            returncode=0, stdout=b"long",
                        ))
    with pytest.raises(hygiene.AuditError, match="git_file_list_too_large"):
        hygiene.tracked_paths(tmp_path)


def test_hygiene_missing_tracked_files_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hygiene, "tracked_paths", lambda _root: [])
    assert hygiene.audit(tmp_path, 100, False, []) == 2


def test_hygiene_strict_advisory_returns_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "no_newline.md").write_bytes(b"abc")
    monkeypatch.setattr(hygiene, "tracked_paths",
                        lambda _root: [Path("no_newline.md")])
    assert hygiene.audit(tmp_path, 100, False, []) == 0
    assert hygiene.audit(tmp_path, 100, True, []) == 1


def test_hygiene_invalid_cli_and_dry_run(tmp_path: Path) -> None:
    assert hygiene.main(["--repo", str(tmp_path), "--max-file-mib", "0"]) == 2
    assert hygiene.main(["--repo", str(tmp_path / "missing")]) == 2
    assert hygiene.main(["--repo", str(tmp_path), "--dry-run"]) == 0


def test_maintenance_json_formatters_include_status() -> None:
    record = logging.LogRecord("synthetic", logging.WARNING, __file__, 0, "test", (), None)
    for formatter in (actions.JsonFormatter(), hygiene.JsonFormatter(), workflows.JsonFormatter()):
        data = formatter.format(record)
        assert '"level":"WARNING"' in data
        assert '"event":"test"' in data
