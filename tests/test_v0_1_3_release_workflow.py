"""Release 0.1.3 must be independently verifiable without rewriting historical tags."""
from pathlib import Path

from shards_kernel._version import __version__


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-v0.1.3.yml"
LEGACY = ROOT / ".github" / "workflows" / "publish-v0.1.2.yml"


def test_release_0_1_3_version_and_one_shot_protection():
    assert __version__ == "0.1.3"
    current = WORKFLOW.read_text(encoding="utf-8")
    historical = LEGACY.read_text(encoding="utf-8")
    assert "name: Publish Shards-Kernel v0.1.3" in current
    assert "branches: [main]" in current
    assert '      - ".github/workflows/publish-v0.1.3.yml"' in current
    assert "shards-kernel-v0.1.3-github-release" in current
    assert "gh release create v0.1.3" in current
    assert "gh workflow run publish.yml" in current
    assert "--field release_tag=v0.1.3" in current
    assert "--ref v0.1.3" in current
    assert "--ref main" not in current
    assert "Verify published PyPI artifacts and fresh installation" in current
    assert "https://pypi.org/pypi/shards-kernel/" in current
    assert "Published PyPI artifact hash differs from verified GitHub release" in current
    assert "shards-kernel[crypto]==0.1.3" in current
    assert "--index-url https://pypi.org/simple" in current
    publisher = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "github.ref == format('refs/tags/{0}', inputs.release_tag)" in publisher
    assert 'test "$GITHUB_REF" = "refs/tags/$RELEASE_TAG"' in publisher
    assert "Publisher checkout differs from release tag commit" in publisher
    assert "github.ref == 'refs/heads/main'" not in publisher
    assert "sha256sum -c SHA256SUMS" in current
    assert "sha256sum --check --strict SHA256SUMS" in current
    assert "cmp -- dist/SHA256SUMS" in current
    assert "verify_candidate_wheel_concurrency.py" in current
    assert "verify_candidate_wheel_permit_scope.py" in current
    assert 'pip install "$wheel[crypto,mcp]"' in current

    # Only the short-lived release job may receive write permissions; pip
    # installs and tests must run in the previous read-only job.
    verify_pos = current.index("  verify:\n")
    release_pos = current.index("  release:\n")
    pypi_pos = current.index("  verify-pypi:\n")
    assert verify_pos < release_pos < pypi_pos
    verify_job = current[verify_pos:release_pos]
    release_job = current[release_pos:pypi_pos]
    published_job = current[pypi_pos:]
    assert "permissions:\n  contents: read" in current[:verify_pos]
    assert "contents: write" not in verify_job
    assert "actions: write" not in verify_job
    assert "python -m pip install" in verify_job
    assert "actions/upload-artifact@" in verify_job
    assert "needs: verify" in release_job
    assert "contents: write" in release_job
    assert "actions: write" in release_job
    assert "actions/download-artifact@" in release_job
    assert "python -m pip install" not in release_job
    assert "needs: release" in published_job
    assert "contents: write" not in published_job
    assert "actions/download-artifact@" in published_job

    # Verification must precede dispatch. Bind the downstream publisher to
    # the exact checked main SHA and verified SHA256 digests, not a mutable
    # GitHub Release checksum file or floating main branch.
    assert release_job.index("cmp -- dist/SHA256SUMS") < release_job.index("gh workflow run publish.yml")
    assert release_job.index('tag_commit="$(git ls-remote') < release_job.index("gh workflow run publish.yml")
    assert release_job.index("gh release edit v0.1.3") < release_job.index("gh workflow run publish.yml")
    for field in ("expected_commit", "expected_wheel_sha256", "expected_sdist_sha256"):
        assert "--field " + field + "=" in release_job
        assert field in publisher
    assert 'Publisher wheel differs from exact verified artifact' in publisher
    assert 'Publisher source differs from exact verified artifact' in publisher
    assert 'Publisher checkout differs from verified release commit' in publisher
    assert "gh release create v0.1.3" in release_job
    assert "--draft" in release_job
    assert "gh release upload v0.1.3" in release_job
    assert "--clobber" not in release_job

    # Security acceptance probes are existing repository scripts, not names
    # asserted without checking that executable test files actually exist.
    for name in ("verify_candidate_wheel_concurrency.py", "verify_candidate_wheel_permit_scope.py"):
        assert (ROOT / "scripts" / "ci" / name).is_file()
        assert name in verify_job

    assert "continue-on-error: true" not in current
    assert "if: always()" not in current
    assert "name: Publish Shards-Kernel v0.1.2" in historical
    assert "gh release create v0.1.2" in historical


def test_public_install_guides_target_release_0_1_3():
    for path in ("README.md", "docs/guides/QUICKSTART.md", "docs/guides/SETUP.md", "docs/PACKAGE_MIGRATION.md"):
        content = (ROOT / path).read_text(encoding="utf-8")
        assert 'shards-kernel==0.1.3' in content or 'shards-kernel[crypto]==0.1.3' in content, path
