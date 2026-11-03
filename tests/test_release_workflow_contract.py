"""Hermetic regression tests for the one-shot v0.1.1 release boundaries.

GitHub and git commands are replaced with local fixtures: no publishing,
credentials, network access, or production side effects occur in these tests.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

import pytest

from shards_kernel._version import __version__


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/publish-v0.1.1.yml").read_text(encoding="utf-8")
CREATE_STEP = "Publish GitHub Release with checksummed wheel and source"
VERIFY_STEP = "Verify published GitHub release before PyPI handoff"
DISPATCH_STEP = "Dispatch verified trusted PyPI publisher"


def _step_script(name: str) -> str:
    """Read a literal YAML run block without pulling in a YAML parser."""
    lines = WORKFLOW.splitlines()
    marker = "      - name: " + name
    try:
        step = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"Missing workflow step: {name}") from exc
    start = None
    for index in range(step + 1, len(lines)):
        if lines[index].startswith("      - name: "):
            break
        if lines[index] == "        run: |":
            start = index + 1
            break
    assert start is not None, f"Missing literal run block for {name}"
    body = []
    for line in lines[start:]:
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    return "\n".join(body) + "\n"


def _run_mocked_release(tmp_path: Path, **flags: str) -> tuple[int, str]:
    """Simulate three sequential release steps with only temporary executables."""
    binary_dir = tmp_path / "mock-bin"
    binary_dir.mkdir()
    log = tmp_path / "commands.log"
    marker = tmp_path / "created-release"
    gh = binary_dir / "gh"
    gh.write_text(
        """#!/usr/bin/env bash
set -eu
printf 'gh:%s\\n' "$*" >> "$COMMAND_LOG"
case "$1:$2" in
  "release:view")
    if [ "${RELEASE_ALREADY_EXISTS:-0}" = "1" ]; then exit 0; fi
    if [ -f "$CREATED_MARKER" ]; then
      if [ "${RELEASE_ASSETS_INVALID:-0}" = "1" ]; then
        printf 'false\\n'
      else
        printf 'true\\n'
      fi
      exit 0
    fi
    exit 1
    ;;
  "release:create")
    if [ "${CREATE_FAIL:-0}" = "1" ]; then exit 1; fi
    touch "$CREATED_MARKER"
    ;;
  "workflow:run")
    ;;
  *) exit 97 ;;
esac
""",
        encoding="utf-8",
    )
    git = binary_dir / "git"
    git.write_text(
        """#!/usr/bin/env bash
set -eu
printf 'git:%s\\n' "$*" >> "$COMMAND_LOG"
case "$1" in
  ls-remote)
    case "${TAG_LOOKUP:-absent}" in
      present) printf '%s refs/tags/v0.1.1\\n' "$GITHUB_SHA" ;;
      error) exit 128 ;;
    esac
    ;;
  *) exit 98 ;;
esac
""",
        encoding="utf-8",
    )
    gh.chmod(0o700)
    git.chmod(0o700)
    (tmp_path / "dist").mkdir()
    for filename in (
        "shards_kernel-0.1.1-py3-none-any.whl",
        "shards_kernel-0.1.1.tar.gz",
        "SHA256SUMS",
    ):
        (tmp_path / "dist" / filename).write_bytes(b"test fixture only")

    env = {
        **os.environ,
        "PATH": str(binary_dir) + os.pathsep + os.environ.get("PATH", ""),
        "GITHUB_REPOSITORY": "Shards-foundation/Shards-kernel",
        "GITHUB_SHA": "a" * 40,
        "RUNNER_TEMP": str(tmp_path),
        "GH_TOKEN": "local-fixture-not-a-credential",
        "COMMAND_LOG": str(log),
        "CREATED_MARKER": str(marker),
        **flags,
    }
    for step in (CREATE_STEP, VERIFY_STEP, DISPATCH_STEP):
        run = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", _step_script(step)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if run.returncode:
            return run.returncode, log.read_text() if log.exists() else ""
    return 0, log.read_text(encoding="utf-8")


def test_release_candidate_version_reports_0_1_1():
    assert __version__ == "0.1.1"
    assert distribution("shards-kernel").version == "0.1.1"
    result = subprocess.run(
        [sys.executable, "-m", "shards_kernel", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "shards-kernel 0.1.1"


def test_release_verification_gates_and_order_are_explicit():
    steps = re.findall(r"^      - name: (.+)$", WORKFLOW, re.MULTILINE)
    required = (
        "Verify release version",
        "Verify lint",
        "Mandatory real-process local E2E gate",
        "Verify complete branch-aware test coverage and governance",
        "Smoke tests and documented demos",
        "Audit declared dependencies and Python security",
        "Build and validate distribution artifacts",
        "Verify installed wheel in a fresh virtual environment",
        CREATE_STEP,
        VERIFY_STEP,
        DISPATCH_STEP,
    )
    indices = [steps.index(name) for name in required]
    assert indices == sorted(indices)
    for command in (
        '__version__ != "0.1.1"',
        "ruff check . --select E,F --ignore E501",
        "python scripts/ci/run_e2e_gate.py",
        "--cov-branch",
        "--cov-fail-under=90",
        "not math.isfinite(coverage) or coverage < 90.0",
        "python scripts/ci/check_governance_coverage.py coverage.json",
        "./scripts/smoke.sh",
        "python examples/01_minimal_request.py",
        "python examples/04_sqlite_persistent_ledger.py",
        "python -m pip check",
        "pip-audit .",
        "bandit -r shards_kernel implementations -ll",
        "python -m build",
        "python scripts/ci/check_wheel_identity.py dist/*.whl",
        "twine check dist/*.whl dist/*.tar.gz",
        "sha256sum -c SHA256SUMS",
        "python -m venv",
        "pip install --no-deps dist/*.whl",
    ):
        assert command in WORKFLOW
    assert "continue-on-error: true" not in WORKFLOW
    assert "if: always()" not in WORKFLOW


@pytest.mark.parametrize(
    "flags",
    [
        {"RELEASE_ALREADY_EXISTS": "1"},
        {"TAG_LOOKUP": "present"},
        {"TAG_LOOKUP": "error"},
    ],
)
def test_existing_release_tag_or_lookup_failure_refuses_publication(tmp_path, flags):
    status, calls = _run_mocked_release(tmp_path, **flags)
    assert status != 0
    assert "gh:release create" not in calls
    assert "gh:workflow run" not in calls


def test_failed_github_release_creation_blocks_pypi_dispatch(tmp_path):
    status, calls = _run_mocked_release(tmp_path, CREATE_FAIL="1")
    assert status != 0
    assert "gh:release create" in calls
    assert "gh:workflow run" not in calls


def test_unverified_release_assets_block_pypi_dispatch(tmp_path):
    status, calls = _run_mocked_release(tmp_path, RELEASE_ASSETS_INVALID="1")
    assert status != 0
    assert "gh:release create" in calls
    assert "gh:workflow run" not in calls


def test_pypi_dispatch_occurs_only_after_verified_github_release(tmp_path):
    status, calls = _run_mocked_release(tmp_path)
    assert status == 0
    created = calls.index("gh:release create")
    confirmed = calls.rindex("gh:release view")
    dispatched = calls.index("gh:workflow run")
    assert created < confirmed < dispatched
    assert "publish.yml" in calls
    assert "release_tag=v0.1.1" in calls
