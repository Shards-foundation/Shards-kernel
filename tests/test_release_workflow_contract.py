"""Hermetic regression tests for the one-shot v0.1.2 release boundaries.

GitHub and git commands are replaced with local fixtures: no publishing,
credentials, network access, or production side effects occur in these tests.
"""

from __future__ import annotations

import hashlib
import zipfile
import os
import re
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

import pytest

from shards_kernel._version import __version__


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/publish-v0.1.2.yml").read_text(encoding="utf-8")
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
  "release:download")
    if [ ! -f "$CREATED_MARKER" ]; then exit 1; fi
    destination=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --dir) destination="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    test -n "$destination"
    cp "$ARTIFACTS_DIR/"* "$destination/"
    if [ "${RELEASE_ASSETS_TAMPERED:-0}" = "1" ]; then
      printf 'altered content' >> "$destination/shards_kernel-0.1.2-py3-none-any.whl"
    fi
    if [ "${RELEASE_CHECKSUMS_TAMPERED:-0}" = "1" ]; then
      printf 'altered checksum' >> "$destination/SHA256SUMS"
    fi
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
      present) printf '%s refs/tags/v0.1.2\\n' "$GITHUB_SHA" ;;
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
    artifacts = tmp_path / "dist"
    artifacts.mkdir()
    artifact_names = (
        "shards_kernel-0.1.2-py3-none-any.whl",
        "shards_kernel-0.1.2.tar.gz",
    )
    checksum_lines = []
    for filename in artifact_names:
        payload = ("test fixture only: " + filename).encode("utf-8")
        (artifacts / filename).write_bytes(payload)
        checksum_lines.append(hashlib.sha256(payload).hexdigest() + "  " + filename)
    (artifacts / "SHA256SUMS").write_text(
        "\n".join(checksum_lines) + "\n", encoding="utf-8"
    )

    env = {
        **os.environ,
        "PATH": str(binary_dir) + os.pathsep + os.environ.get("PATH", ""),
        "GITHUB_REPOSITORY": "Shards-foundation/Shards-kernel",
        "GITHUB_SHA": "a" * 40,
        "RUNNER_TEMP": str(tmp_path),
        "GH_TOKEN": "local-fixture-not-a-credential",
        "COMMAND_LOG": str(log),
        "CREATED_MARKER": str(marker),
        "ARTIFACTS_DIR": str(artifacts),
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


@pytest.mark.parametrize("corrupt_description", [False, True])
def test_wheel_readme_metadata_utf8_validation(tmp_path, corrupt_description):
    """Reproduce wheel metadata's non-ASCII body, including the em dash."""
    readme = (
        "# Shards-Kernel — Deterministic Control Planes for AI Systems\n"
        "![Shards-Kernel branded banner](docs/images/shards-kernel-banner.svg)\n"
        "[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)\n"
        "## When to use Shards-Kernel\n"
        "shards-kernel demo --json\n"
        "shards-kernel[crypto]==0.1.2\n"
    )
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    metadata_description = readme.replace("Shards-Kernel", "Altered-Kernel", 1) if corrupt_description else readme
    header = (
        "Metadata-Version: 2.4\n"
        "Name: shards-kernel\n"
        "Version: 0.1.2\n"
        "Description-Content-Type: text/markdown\n\n"
    ).encode("ascii")
    with zipfile.ZipFile(dist / "shards_kernel-0.1.2-py3-none-any.whl", "w") as wheel:
        wheel.writestr(
            "shards_kernel-0.1.2.dist-info/METADATA",
            header + metadata_description.encode("utf-8"),
        )
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c",
         _step_script("Verify PyPI README description is embedded in wheel")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if corrupt_description:
        assert result.returncode != 0
        assert "differs from committed README" in result.stderr
    else:
        assert result.returncode == 0, result.stderr


def test_current_package_version_is_0_1_3_without_mutating_historical_0_1_2_release():
    assert __version__ == "0.1.3"
    assert distribution("shards-kernel").version == "0.1.3"
    result = subprocess.run(
        [sys.executable, "-m", "shards_kernel", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "shards-kernel 0.1.3"


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
        "Verify PyPI README description is embedded in wheel",
        CREATE_STEP,
        VERIFY_STEP,
        DISPATCH_STEP,
    )
    indices = [steps.index(name) for name in required]
    assert indices == sorted(indices)
    for command in (
        '__version__ != "0.1.2"',
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
    assert 'metadata.get_payload(decode=True)' in WORKFLOW
    assert 'payload.decode("utf-8", errors="strict")' in WORKFLOW
    assert 'cmp -- dist/SHA256SUMS "$verify_dir/SHA256SUMS"' in WORKFLOW
    assert 'sha256sum --check --strict SHA256SUMS' in WORKFLOW
    assert 'cmp -- "$local_artifact" "$verify_dir/$(basename "$local_artifact")"' in WORKFLOW
    assert "readme.strip() != description.strip()" in WORKFLOW
    assert '"## When to use Shards-Kernel"' in WORKFLOW
    assert 'metadata.get("Version") != "0.1.2"' in WORKFLOW
    assert "gh workflow run publish.yml" in WORKFLOW
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


@pytest.mark.parametrize(
    "flags",
    [
        {"RELEASE_ASSETS_TAMPERED": "1"},
        {"RELEASE_CHECKSUMS_TAMPERED": "1"},
    ],
)
def test_changed_release_bytes_prevent_pypi_dispatch(tmp_path, flags):
    status, calls = _run_mocked_release(tmp_path, **flags)
    assert status != 0
    assert "gh:release create" in calls
    assert "gh:release download" in calls
    assert "gh:workflow run" not in calls


def test_pypi_dispatch_occurs_only_after_verified_github_release(tmp_path):
    status, calls = _run_mocked_release(tmp_path)
    assert status == 0
    created = calls.index("gh:release create")
    confirmed = calls.rindex("gh:release view")
    dispatched = calls.index("gh:workflow run")
    assert created < confirmed < dispatched
    assert "publish.yml" in calls
    assert "release_tag=v0.1.2" in calls
