"""Negative-path verification of the mandatory local E2E release gate.

Real subprocess probes exercise pytest collection and reporting, rather than
only asserting implementation details of StrictE2EGate.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
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
    # Only synthetic test file paths are injected into this subprocess. The
    # production runner's reviewed SCENARIOS list is never altered on disk.
    script = textwrap.dedent(
        f"""\
        from scripts.ci import run_e2e_gate as gate
        gate.SCENARIOS = ({str(scenario) + '::test_case'!r},)
        raise SystemExit(gate.main())
        """
    )
    environ = os.environ.copy()
    environ["PYTHONPATH"] = str(ROOT) + os.pathsep + environ.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=environ,
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )
    if should_pass:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout
    else:
        assert result.returncode != 0, (mode, result.stdout, result.stderr)
        if mode in {"skipped", "xfail", "xpass"}:
            assert "E2E RELEASE GATE FAILED" in result.stderr


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
    # CI once reported a <90% pytest-cov result as a successful quality job.
    # An independent coverage CLI step must enforce the numeric threshold.
    assert "python -m coverage report --fail-under=90" in quality_job
    assert "--cov=scripts.ci.run_e2e_gate" in quality_job
    assert "sys.version_info >= (3, 11)" in quality_job
