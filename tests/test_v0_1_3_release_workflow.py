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

    # Test/build work is read-only. Only the isolated release job may write
    # GitHub assets; the post-release dispatcher may only launch a workflow.
    verify_pos = current.index("  verify:\n")
    release_pos = current.index("  release:\n")
    dispatch_pos = current.index("  dispatch:\n")
    pypi_pos = current.index("  verify-pypi:\n")
    assert verify_pos < release_pos < dispatch_pos < pypi_pos
    verify_job = current[verify_pos:release_pos]
    release_job = current[release_pos:dispatch_pos]
    dispatch_job = current[dispatch_pos:pypi_pos]
    published_job = current[pypi_pos:]
    assert "permissions:\n  contents: read" in current[:verify_pos]
    assert "contents: write" not in verify_job
    assert "actions: write" not in verify_job
    assert "python -m pip install" in verify_job
    assert "actions/upload-artifact@" in verify_job
    assert "needs: verify" in release_job
    assert "contents: write" in release_job
    assert "actions: write" not in release_job
    assert "actions/download-artifact@" in release_job
    assert "python -m pip install" not in release_job
    assert "needs: release" in dispatch_job
    assert "actions: write" in dispatch_job
    assert "contents: write" not in dispatch_job
    assert "python -m pip install" not in dispatch_job
    assert "needs: dispatch" in published_job
    assert "contents: write" not in published_job
    assert "actions/download-artifact@" in published_job

    # PyPI dispatch cannot precede release/tag/byte verification, because
    # the dispatcher is a separate job depending on successful release.
    assert "gh workflow run publish.yml" not in release_job
    assert release_job.index("cmp -- dist/SHA256SUMS") < release_job.index("gh release edit v0.1.3")
    assert release_job.index('tag_commit="$(git ls-remote') < release_job.index("gh release edit v0.1.3")
    assert "gh workflow run publish.yml" in dispatch_job
    assert '--field verified_run_id="$GITHUB_RUN_ID"' in dispatch_job
    for untrusted in ("expected_commit", "expected_wheel_sha256", "expected_sdist_sha256"):
        assert untrusted not in publisher
        assert "--field " + untrusted not in current

    # A manual caller may select a run ID but cannot supply the publisher's
    # hashes. Publisher independently queries GitHub for the protected-main
    # workflow provenance, completed verify/release jobs, and downloads the
    # Actions build from that authenticated run, not public release assets.
    assert "VERIFIED_RUN_ID" in publisher
    assert 'gh api "/repos/$GITHUB_REPOSITORY/actions/runs/$VERIFIED_RUN_ID"' in publisher
    assert '.event == "push"' in publisher
    assert '.head_branch == "main"' in publisher
    assert '.head_sha == $sha' in publisher
    assert "publish-v0.1.3.yml@refs/heads/main" in publisher
    assert "jobs?per_page=100&filter=latest" in publisher
    assert "Verify v0.1.3 source and clean installed wheel" in publisher
    assert "Publish immutable v0.1.3 GitHub assets" in publisher
    assert 'gh run download "$VERIFIED_RUN_ID"' in publisher
    assert "Public release asset differs from authenticated verified run" in publisher
    assert "cmp --" in publisher
    assert "sha256sum --check --strict SHA256SUMS" in publisher
    assert "gh release create v0.1.3" in release_job
    assert "--draft" in release_job
    assert "gh release upload v0.1.3" in release_job
    assert "--clobber" not in release_job

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


def test_busy_audit_rejects_generic_denials_and_empty_evidence():
    """A generic DENY must not pass the genuine KERNEL_BUSY release gate."""
    from scripts.ci.verify_candidate_wheel_concurrency import (
        ACTOR,
        WORKERS,
        assess_busy_audit,
    )

    def receipt(i, *, error="KERNEL_BUSY: single-flight admission in progress"):
        return {
            "request_id": f"req-{i}",
            "decision": "DENY",
            "error": error,
            "evidence_hash": f"evidence-{i}",
        }

    def audit(r):
        return {
            "request_id": r["request_id"],
            "decision": "DENY",
            "audit_phase": "outcome",
            "error": r["error"],
            "entry_hash": r["evidence_hash"],
            "actor": ACTOR,
        }

    contention = [receipt(i) for i in range(WORKERS - 1)]
    all_receipts = [*contention]
    verified_audits = [audit(r) for r in all_receipts]
    assert assess_busy_audit(contention, all_receipts, verified_audits) == (
        True, True, WORKERS - 1,
    )

    generic = [dict(r, error="PERMIT_DENIED: synthetic") for r in contention]
    generic_audit = [audit(r) for r in generic]
    assert assess_busy_audit(generic, generic, generic_audit) == (False, False, 0)
    assert assess_busy_audit(generic, generic, []) == (False, False, 0)
    assert assess_busy_audit(contention, all_receipts, []) == (True, False, 0)
    assert assess_busy_audit(contention, all_receipts, verified_audits[:-1]) == (
        True, False, WORKERS - 2,
    )
    corrupted = [dict(row) for row in verified_audits]
    corrupted[0]["entry_hash"] = "mismatched"
    assert assess_busy_audit(contention, all_receipts, corrupted)[1] is False
