"""Verify GitHub Actions use reviewed immutable upstream commits.

Python 3.9+, standard library only. No GitHub API traffic, credentials or
workflow executions are involved.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
SHA_PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.\-/]+@[a-f0-9]{40}$")
DOCKER_DIGEST = re.compile(r"^docker://[^#\s]+@sha256:[a-f0-9]{64}$")
CODEQL_COMMIT = "33d7b85da1a04171e211befe2c739303b9a4c066"
JEKYLL_COMMIT = "44a6e6beabd48582f863aeeb6cb2151cc1716697"


def read_workflow(filename: str) -> str:
    """Read a known workflow as UTF-8 source."""
    return (WORKFLOWS / filename).read_text(encoding="utf-8")


class WorkflowPinContract(unittest.TestCase):
    """Fail closed when upstream action dependencies become floating."""

    def test_every_remote_action_is_immutable(self) -> None:
        files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
        self.assertTrue(files, "No workflow definitions found")
        total = 0
        for path in files:
            source = path.read_text(encoding="utf-8")
            for match in USES.finditer(source):
                ref = match.group(1)
                total += 1
                if ref.startswith("./"):
                    continue
                with self.subTest(workflow=path.name, action=ref):
                    if ref.startswith("docker://"):
                        self.assertRegex(ref, DOCKER_DIGEST)
                    else:
                        self.assertRegex(ref, SHA_PINNED)
        self.assertGreater(total, 0, "No GitHub Actions references found")

    def test_codeql_actions_match_verified_release_commit(self) -> None:
        occurrences = 0
        for filename in ("codeql.yml", "security.yml"):
            source = read_workflow(filename)
            for match in USES.finditer(source):
                ref = match.group(1)
                if ref.startswith("github/codeql-action/"):
                    occurrences += 1
                    self.assertTrue(
                        ref.endswith("@" + CODEQL_COMMIT),
                        f"{filename}: unexpected CodeQL commit",
                    )
        self.assertEqual(occurrences, 5)

    def test_jekyll_build_pages_matches_verified_release_commit(self) -> None:
        source = read_workflow("jekyll-gh-pages.yml")
        uses = [match.group(1) for match in USES.finditer(source)]
        self.assertIn("actions/jekyll-build-pages@" + JEKYLL_COMMIT, uses)

    def test_pinned_release_annotations_are_present(self) -> None:
        for filename in ("codeql.yml", "security.yml"):
            source = read_workflow(filename)
            self.assertIn(CODEQL_COMMIT + " # v4.39.3", source)
        self.assertIn(
            JEKYLL_COMMIT + " # v1.0.13",
            read_workflow("jekyll-gh-pages.yml"),
        )


if __name__ == "__main__":
    unittest.main()
