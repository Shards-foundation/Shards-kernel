"""Static, dependency-free guardrails for Shards-Kernel legal documentation.

These checks test documentation consistency and a PR's changed-file scope;
they are NOT a legal opinion, a data-flow audit or a GDPR certification.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGAL_DOCUMENTS = frozenset(
    {
        "TERMS_OF_SERVICE.md",
        "PRIVACY_POLICY.md",
        "docs/legal/ADOPTION_CHECKLIST.md",
    }
)
# Legal policy changes must remain separate from runtime, telemetry, package,
# release, licensing and infrastructure changes. Those need independent review.
ALLOWED_WITH_LEGAL_CHANGES = LEGAL_DOCUMENTS | {
    "README.md",
    "docs/README.md",
    "tests/test_legal_docs.py",
    ".github/workflows/docs.yml",
}


def read_document(path):
    """Read an expected repository document using the project root."""
    return (ROOT / path).read_text(encoding="utf-8")


def illegal_legal_pr_paths(changed_paths):
    """Return prohibited paths if the change includes any legal policy file."""
    changes = set(changed_paths)
    if not changes.intersection(LEGAL_DOCUMENTS):
        return []
    return sorted(changes.difference(ALLOWED_WITH_LEGAL_CHANGES))


def git_executable():
    """Prefer a trusted system Git; never execute a git binary from this repo."""
    system_git = Path("/usr/bin/git")
    if system_git.is_file():
        return str(system_git)
    discovered = shutil.which("git")
    if not discovered:
        raise RuntimeError("Git executable is required for legal change-scope tests")
    resolved = Path(discovered).resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise RuntimeError("Refusing Git executable supplied by repository content")
    return str(resolved)


def changed_files_since_merge_base(base, head, root=ROOT):
    """List only PR-introduced changes, excluding unrelated base-branch commits."""
    changed = subprocess.check_output(
        [git_executable(), "diff", "--name-only", "-z", f"{base}...{head}"],
        cwd=root,
    )
    return [os.fsdecode(p) for p in changed.split(b"\0") if p]


class LegalDocumentationContractTests(unittest.TestCase):
    """Mechanical guardrails, deliberately not an assessment of legal validity."""

    def test_readme_legal_links_point_to_existing_documents(self):
        readme = read_document("README.md")
        self.assertIn("## Legal / Privacy (Review Drafts)", readme)
        section = readme.split("## Legal / Privacy (Review Drafts)", 1)[1].split(
            "\n## ", 1
        )[0]
        for path in sorted(LEGAL_DOCUMENTS):
            with self.subTest(link=path):
                self.assertIn("](" + path + ")", section)
                self.assertTrue((ROOT / path).is_file(), path)
        self.assertIn("](LICENSE)", section)
        self.assertTrue((ROOT / "LICENSE").is_file())

    def test_all_three_documents_and_readme_express_draft_status(self):
        for path in sorted(LEGAL_DOCUMENTS):
            with self.subTest(document=path):
                text = read_document(path)
                self.assertRegex(
                    text[:550].lower(),
                    r"\*\*(?:document status|status):\*\*[^\n]*\bdraft\b[^\n]*\bnot adopted\b",
                )
        readme = read_document("README.md").lower()
        self.assertIn("these documents are drafts", readme)
        self.assertIn("have not been formally adopted", readme)

    def test_mit_licence_and_precedence_are_preserved(self):
        licence = read_document("LICENSE")
        terms = read_document("TERMS_OF_SERVICE.md").lower()
        readme = read_document("README.md").lower()
        for statement in (
            "MIT License",
            "Permission is hereby granted, free of charge",
            "without restriction",
            'THE SOFTWARE IS PROVIDED "AS IS"',
        ):
            with self.subTest(licence_statement=statement):
                self.assertIn(statement, licence)
        self.assertIn(
            "nothing in these terms amends, conditions or restricts", terms
        )
        self.assertIn("the software licence governs your use", terms)
        self.assertIn(
            "do not impose additional restrictions on your mit-licensed software rights",
            terms,
        )
        self.assertIn("mit licence", readme)

    def test_current_scope_is_local_open_source_not_hosted_financial_saas(self):
        terms = read_document("TERMS_OF_SERVICE.md").lower()
        privacy = read_document("PRIVACY_POLICY.md").lower()
        self.assertIn("open-source python software library", terms)
        self.assertIn("not a hosted trading platform", terms)
        self.assertIn("production-hosted shards mcp gateway", terms)
        self.assertIn("not** a central hosted shards account", privacy)
        self.assertIn("there is no project-operated central service", privacy)
        self.assertIn(
            "not automatically sent to, held by or controlled by the project publisher",
            privacy,
        )
        self.assertIn("organisation deploying the software", privacy)
        unqualified_hosted_claim = re.compile(
            r"\b(?:we|shards inc(?: ltd)?|the publisher)\s+"
            r"(?:currently\s+)?(?:operate|provide|offer|host)\s+"
            r"(?:a|an|the)\s+(?:paid\s+)?"
            r"(?:hosted|managed|production|saas|trading|wallet)\b",
            re.IGNORECASE,
        )
        for name, text in (("terms", terms), ("privacy", privacy)):
            with self.subTest(document=name):
                self.assertIsNone(unqualified_hosted_claim.search(text))

    def test_doc_only_change_scope_allows_original_policy_pr_files(self):
        self.assertEqual(
            illegal_legal_pr_paths(
                [
                    "TERMS_OF_SERVICE.md",
                    "PRIVACY_POLICY.md",
                    "README.md",
                    "docs/legal/ADOPTION_CHECKLIST.md",
                ]
            ),
            [],
        )

    def test_original_legal_policy_merge_contains_only_four_markdown_files(self):
        """Verify PR #95's actual merged commit, not a hard-coded fake file list."""
        if os.environ.get("LEGAL_DOC_SCOPE_REQUIRED") != "true":
            return  # The Docs job checks real history; regular CI uses a shallow checkout.
        original_merge = "e5cef4c9e85392662e38075cd8cb326799651102"
        parent = subprocess.check_output(
            [git_executable(), "rev-parse", original_merge + "^"],
            cwd=ROOT,
        ).decode().strip()
        actual = changed_files_since_merge_base(parent, original_merge)
        self.assertEqual(
            set(actual),
            {
                "TERMS_OF_SERVICE.md",
                "PRIVACY_POLICY.md",
                "README.md",
                "docs/legal/ADOPTION_CHECKLIST.md",
            },
            "PR #95 must not have modified runtime, telemetry, packaging or infra",
        )

    def test_doc_only_change_scope_rejects_code_telemetry_release_and_licence(self):
        for forbidden in (
            "shards_kernel/api.py",
            "shards_kernel/telemetry/collector.py",
            "implementations/storage.py",
            "pyproject.toml",
            "LICENSE",
            ".github/workflows/publish.yml",
            "scripts/ci/run_e2e_gate.py",
        ):
            with self.subTest(path=forbidden):
                self.assertEqual(
                    illegal_legal_pr_paths(["PRIVACY_POLICY.md", forbidden]),
                    [forbidden],
                )

    def test_diff_excludes_unrelated_changes_on_diverged_base_branch(self):
        """A base-only runtime commit must not be blamed on a legal-only PR."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    [git_executable(), *args], cwd=repo
                ).decode().strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Legal CI Test")
            git("config", "user.email", "legal-ci@example.invalid")
            (repo / "PRIVACY_POLICY.md").write_text("draft\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "Initial")
            git("checkout", "-qb", "legal-policy")
            (repo / "PRIVACY_POLICY.md").write_text("draft revised\n", encoding="utf-8")
            git("commit", "-qam", "Update legal policy")
            legal_head = git("rev-parse", "HEAD")
            git("checkout", "-q", "main")
            (repo / "runtime.py").write_text("def run():\n    return True\n", encoding="utf-8")
            git("add", "runtime.py")
            git("commit", "-qm", "Unrelated base branch runtime change")
            current_base = git("rev-parse", "HEAD")
            self.assertEqual(
                changed_files_since_merge_base(current_base, legal_head, root=repo),
                ["PRIVACY_POLICY.md"],
            )
            self.assertEqual(
                illegal_legal_pr_paths(
                    changed_files_since_merge_base(current_base, legal_head, root=repo)
                ),
                [],
            )

    def test_pull_request_diff_does_not_mix_legal_and_runtime_changes(self):
        """When CI provides PR SHAs, verify the real git diff, not a hand-written list."""
        base = os.environ.get("LEGAL_PR_BASE_SHA", "")
        head = os.environ.get("LEGAL_PR_HEAD_SHA", "")
        if not base and not head:
            if os.environ.get("LEGAL_DOC_SCOPE_REQUIRED") == "true":
                self.fail("Missing PR base/head SHA: cannot verify legal change scope")
            return
        self.assertRegex(base, r"\A[0-9a-f]{40}\Z")
        self.assertRegex(head, r"\A[0-9a-f]{40}\Z")
        paths = changed_files_since_merge_base(base, head)
        self.assertTrue(paths, "PR diff is empty or cannot be established")
        rejected = illegal_legal_pr_paths(paths)
        self.assertEqual(
            rejected,
            [],
            "Legal policy changes must not be mixed with runtime, telemetry, "
            "licensing, deployment or other unreviewed files: " + ", ".join(rejected),
        )


if __name__ == "__main__":
    unittest.main()
