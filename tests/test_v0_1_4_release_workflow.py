"""Security invariants for the one-shot Shards-Kernel v0.1.4 release handoff.

This regression suite prevents a later edit from treating v0.1.4's mutable
GitHub Release assets as authority instead of the verified Actions artifact.
"""

from pathlib import Path
import os
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_v0_1_4_reuses_protected_main_one_shot_release():
    release = (WORKFLOWS / "publish-v0.1.4.yml").read_text(encoding="utf-8")
    assert "branches: [main]" in release
    assert '".github/workflows/publish-v0.1.4.yml"' in release
    assert "Verify v0.1.4 source and clean installed wheel" in release
    assert "Publish immutable v0.1.4 GitHub assets" in release
    assert "shards-kernel-v0.1.4-verified" in release
    assert "sha256sum --check --strict SHA256SUMS" in release
    assert "cmp -- dist/SHA256SUMS" in release
    assert "gh workflow run publish.yml" in release
    assert "--ref v0.1.4" in release
    assert "--field release_tag=v0.1.4" in release
    assert '--field verified_run_id="$GITHUB_RUN_ID"' in release


def test_publisher_authenticates_v0_1_4_immutable_actions_artifact():
    publisher = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    assert 'if [ "$RELEASE_TAG" = "v0.1.3" ] || [ "$RELEASE_TAG" = "v0.1.4" ]; then' in publisher
    assert 'and .path == ".github/workflows/publish-v0.1.3.yml"' in publisher
    assert 'and .path == ".github/workflows/publish-v0.1.4.yml"' in publisher
    assert "Verify v0.1.4 source and clean installed wheel" in publisher
    assert "Publish immutable v0.1.4 GitHub assets" in publisher
    assert 'gh api "/repos/$GITHUB_REPOSITORY/actions/runs/$VERIFIED_RUN_ID"' in publisher
    assert 'gh run download "$VERIFIED_RUN_ID"' in publisher
    assert '--name "shards-kernel-$RELEASE_TAG-verified"' in publisher
    assert 'test -f "dist/shards_kernel-$version-py3-none-any.whl"' in publisher
    assert 'test -f "dist/shards_kernel-$version.tar.gz"' in publisher
    assert 'cmp -- "$artifact" "$public_dir/$(basename "$artifact")"' in publisher
    assert "Public release asset differs from authenticated verified run" in publisher


def test_publisher_verifies_after_owner_approved_publication():
    release = (WORKFLOWS / "publish-v0.1.4.yml").read_text(encoding="utf-8")
    publisher = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    assert "  verify-pypi:" not in release
    assert "  verify-v0-1-4-pypi:" in publisher
    verification = publisher.split("  verify-v0-1-4-pypi:", 1)[1]
    assert "needs: publish" in verification
    assert "inputs.release_tag == 'v0.1.4'" in verification
    assert "name: verified-pypi-distributions" in verification
    assert "Published PyPI artifact hash differs from verified GitHub release" in verification
    assert "shards-kernel[crypto]==0.1.4" in verification
    assert "    environment:\n      name: pypi" in publisher


@pytest.mark.parametrize("version", ("v0.1.3", "v0.1.4"))
@pytest.mark.parametrize("probe", ("check_release_dispatch_shell.sh", "check_release_tag_shell.sh"))
def test_actual_release_shell_probes(version: str, probe: str):
    env = dict(os.environ, RELEASE_TEST_TAG=version)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "ci" / probe)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, f"{version} {probe}: {result.stdout}\n{result.stderr}"
