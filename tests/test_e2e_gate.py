"""Negative-path verification of the mandatory local E2E release gate.

Real subprocess probes exercise pytest collection and reporting, rather than
only asserting implementation details of StrictE2EGate.
"""

from __future__ import annotations

import io
import multiprocessing
import os
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import run_e2e_gate as gate


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("version", "platform", "expected"),
    [
        ((3, 9), "linux", False),
        ((3, 10), "linux", False),
        ((3, 11), "linux", True),
        ((3, 12), "linux", True),
        ((3, 13), "linux", True),
        ((3, 12), "win32", False),
        ((3, 12), "darwin", False),
    ],
)
def test_e2e_supported_environment(version, platform, expected):
    assert gate.supported_environment(version, platform) is expected


def test_e2e_rejects_unsupported_runtime_before_running_pytest(monkeypatch, capsys):
    monkeypatch.setattr(gate, "supported_environment", lambda: False)

    def must_not_run(*args, **kwargs):
        pytest.fail("Unsupported platform must never execute E2E pytest")

    monkeypatch.setattr(gate.pytest, "main", must_not_run)
    assert gate.main() == 2
    assert "requires Linux and Python 3.11+" in capsys.readouterr().err


def _run_real_process_gate_probe(scenario: str, workdir: str, sender) -> None:
    """Spawned child executes the reviewed gate; no code or shell injection.

    The scenario is an absolute synthetic pytest node ID from our own
    temporary test file, not a command, shell fragment, or interpolated
    Python source. IPC carries back the actual gate exit and output.
    """
    try:
        os.chdir(workdir)
        gate.SCENARIOS = (scenario,)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = gate.main()
        sender.send((exit_code, stdout.getvalue(), stderr.getvalue()))
    except Exception as exc:
        sender.send((2, "", "Probe raised " + type(exc).__name__))
    finally:
        sender.close()


@pytest.mark.parametrize(
    ("mode", "source", "should_pass"),
    [
        ("passing", "def test_case():\n    assert True\n", True),
        ("missing", None, False),
        ("skipped", "import pytest\n@pytest.mark.skip(reason='gate regression')\ndef test_case():\n    assert True\n", False),
        ("xfail", "import pytest\n@pytest.mark.xfail(reason='gate regression')\ndef test_case():\n    assert False\n", False),
        ("xpass", "import pytest\n@pytest.mark.xfail(reason='gate regression')\ndef test_case():\n    assert True\n", False),
        ("failing", "def test_case():\n    assert False\n", False),
    ],
)
@pytest.mark.skipif(
    sys.platform != "linux" or sys.version_info < (3, 11),
    reason="The real E2E gate deliberately requires Linux and Python 3.11+",
)
def test_e2e_gate_pytest_process_fails_closed(tmp_path, mode, source, should_pass):
    """Exercise the actual runner with isolated pytest scenarios in new interpreters."""
    scenario = tmp_path / "test_scenario.py"
    if source is not None:
        scenario.write_text(source, encoding="utf-8")
    # Spawn a separate Python interpreter using a structured IPC channel.
    # No dynamic Python -c code and no command line or shell interpolation.
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    worker = ctx.Process(
        target=_run_real_process_gate_probe,
        args=(str(scenario) + "::test_case", str(tmp_path), sender),
    )
    try:
        worker.start()
        sender.close()
        if not receiver.poll(25):
            worker.terminate()
            pytest.fail("E2E probe did not finish within 25 seconds")
        exit_code, stdout, stderr = receiver.recv()
        worker.join(timeout=5)
        assert worker.exitcode == 0, "Spawned E2E probe exited unexpectedly"
    finally:
        if worker.is_alive():
            worker.terminate()
        if worker.pid is not None:
            worker.join(timeout=5)
        receiver.close()
        sender.close()
    if should_pass:
        assert exit_code == 0, stdout + stderr
        assert "1 passed" in stdout
    else:
        assert exit_code != 0, (mode, stdout, stderr)
        if mode in {"skipped", "xfail", "xpass"}:
            assert "E2E RELEASE GATE FAILED" in stderr


def test_e2e_hook_rejects_deselection_and_counts_only_real_passes(capsys):
    plugin = gate.StrictE2EGate()
    plugin.pytest_collection_finish(SimpleNamespace(items=[object()] * 3))
    for _ in range(3):
        plugin.pytest_runtest_logreport(
            SimpleNamespace(skipped=False, when="call", passed=True)
        )
    session = SimpleNamespace(exitstatus=pytest.ExitCode.OK)
    plugin.pytest_sessionfinish(session, int(pytest.ExitCode.OK))
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
    assert "collected=3" in capsys.readouterr().err


def test_e2e_hook_preserves_success_when_all_scenarios_pass(capsys):
    plugin = gate.StrictE2EGate()
    plugin.pytest_collection_finish(SimpleNamespace(items=[object()] * len(gate.SCENARIOS)))
    for _ in gate.SCENARIOS:
        plugin.pytest_runtest_logreport(
            SimpleNamespace(skipped=False, when="call", passed=True)
        )
    session = SimpleNamespace(exitstatus=pytest.ExitCode.OK)
    plugin.pytest_sessionfinish(session, int(pytest.ExitCode.OK))
    assert session.exitstatus == pytest.ExitCode.OK
    assert capsys.readouterr().err == ""


def test_e2e_hook_does_not_count_non_call_or_xfailed_results():
    plugin = gate.StrictE2EGate()
    plugin.pytest_runtest_logreport(
        SimpleNamespace(skipped=False, when="setup", passed=True)
    )
    plugin.pytest_runtest_logreport(
        SimpleNamespace(skipped=False, when="call", passed=True, wasxfail="expected")
    )
    plugin.pytest_runtest_logreport(
        SimpleNamespace(skipped=True, when="call", passed=False, wasxfail="expected")
    )
    assert plugin.passed == 0
    assert plugin.skipped == 1


def test_ci_quality_matrix_is_structurally_blocked_by_e2e_failure():
    """CI graph invariant: no quality job may bypass the strict E2E dependency."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^  e2e:\s*$", workflow)
    assert re.search(r"(?m)^  quality:\s*\n    needs: e2e\s*$", workflow)
    assert re.search(
        r"(?m)^        run: python scripts/ci/run_e2e_gate\.py\s*$", workflow
    )
    e2e_job = workflow.split("\n  e2e:\n", 1)[1].split("\n  quality:\n", 1)[0]
    quality_job = workflow.split("\n  quality:\n", 1)[1]
    # Either would make a red E2E step ineffective at preventing quality work.
    assert not re.search(r"(?m)^\s*continue-on-error:\s*true\s*$", e2e_job)
    assert not re.search(r"(?m)^\s*if:\s*always\(\)\s*$", quality_job)
    # CI once reported 89.99% coverage as a successful quality job.
    # A separate unrounded JSON check must enforce the exact numerical floor.
    assert 'json.load(report)["totals"]["percent_covered"]' in quality_job
    assert "percent < 90.0" in quality_job
    assert "math.isfinite(percent)" in quality_job
    assert "sys.exit(1)" in quality_job
    assert "--cov=scripts.ci.run_e2e_gate" in quality_job
    assert "sys.version_info >= (3, 11)" in quality_job
