"""Offline contract checks for the privileged pull-request labeler workflow."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/label.yml").read_text(encoding="utf-8")
CONFIG = (ROOT / ".github/labeler.yml").read_text(encoding="utf-8")
PINNED_V7 = "bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13"


def _label_globs() -> dict[str, list[str]]:
    """Extract the repository's deliberately simple changed-files YAML dialect."""
    sections = re.split(r'(?m)^"([^"]+)":\s*$', CONFIG)
    assert sections[0].strip() == ""
    assert len(sections) % 2 == 1
    mappings = {}
    for label, body in zip(sections[1::2], sections[2::2]):
        assert body.count("  - changed-files:") == 1
        assert body.count("      - any-glob-to-any-file:") == 1
        globs = re.findall(r'^          - "([^"\n]+)"$', body, flags=re.MULTILINE)
        assert globs, f"No file globs for {label}"
        assert label not in mappings
        mappings[label] = globs
    return mappings


def test_labeler_action_is_immutable_and_uses_scoped_permissions():
    assert "on: [pull_request_target]" in WORKFLOW
    assert "contents: read" in WORKFLOW
    assert "pull-requests: write" in WORKFLOW
    assert 'repo-token: "${{ secrets.GITHUB_TOKEN }}"' in WORKFLOW
    assert f"uses: actions/labeler@{PINNED_V7} # v7.0.0" in WORKFLOW
    assert "uses: actions/labeler@v7" not in WORKFLOW
    assert "actions/checkout@" not in WORKFLOW  # No untrusted code checkout with write authority.
    assert not re.search(r"(?m)^\s+run:\s*", WORKFLOW)


@pytest.mark.parametrize(
    ("path", "label", "expected"),
    [
        ("shards_kernel/api.py", "area: kernel", True),
        ("shards_kernel/submodule/engine.py", "area: kernel", True),
        ("implementations/storage.py", "area: kernel", True),
        ("implementations/storage/sqlite.py", "area: kernel", True),
        ("kernels/legacy.py", "area: kernel", False),
        ("tests/test_something.py", "area: tests", True),
        ("scripts/ci/check.py", "area: tests", True),
        ("docs/quickstart.md", "area: docs", True),
        (".github/workflows/ci.yml", "area: ci", True),
        ("pyproject.toml", "area: ci", True),
    ],
)
def test_label_mapping_for_representative_changes(path: str, label: str, expected: bool):
    mapping = _label_globs()
    assert "area: kernel" in mapping
    assert "kernels/**" not in mapping["area: kernel"]
    assert any(fnmatchcase(path, pattern) for pattern in mapping[label]) is expected
