"""Protect discoverable Shards-Kernel agent skills against metadata/link drift.

No external agent harness, live operator, secret or cloud service is needed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / ".github" / "skills"
REQUIRED = (
    "get-started",
    "governed-mcp-agent",
    "operator-provisioning",
    "release-verification",
)
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def _read_skill(slug: str) -> tuple[dict[str, str], str]:
    path = SKILLS_ROOT / slug / "SKILL.md"
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n"), f"Missing YAML frontmatter: {path}"
    assert "\n---\n" in content[4:], f"Unterminated YAML frontmatter: {path}"
    header, body = content[4:].split("\n---\n", 1)
    fields: dict[str, str] = {}
    for line in header.splitlines():
        key, sep, value = line.partition(":")
        assert sep and key not in fields, f"Invalid/duplicate field in {path}: {line}"
        assert key in ("name", "description", "license"), f"Unexpected field in {path}"
        assert value.strip(), f"Missing {key} in {path}"
        fields[key] = value.strip()
    assert len(body.strip()) >= 600, f"Missing actionable content in {path}"
    return fields, body


@pytest.mark.parametrize("slug", REQUIRED)
def test_agent_skills_are_discoverable_portable_and_scoped(slug):
    fields, body = _read_skill(slug)
    assert fields["name"] == slug
    assert _SKILL_NAME.fullmatch(slug)
    assert 40 <= len(fields["description"]) <= 1024
    assert fields["license"] == "MIT"
    assert "Shards-Kernel" in body
    assert "permit" in body.lower()
    assert "MCP" in body
    assert "production" in body.lower()
    assert "##" in body


@pytest.mark.parametrize("slug", REQUIRED)
def test_agent_skill_local_markdown_references_exist(slug):
    path = SKILLS_ROOT / slug / "SKILL.md"
    _, body = _read_skill(slug)
    links = _LINK.findall(body)
    assert links, f"Unlinked skill cannot progressively disclose docs: {slug}"
    for href in links:
        if href.startswith(("https://", "http://", "mailto:", "#")):
            continue
        target = href.split("#", 1)[0]
        assert target and not target.startswith("/"), f"Unsafe link: {href}"
        assert (path.parent / target).resolve().is_file(), (
            f"Broken link from {path}: {href}"
        )


def test_root_agent_instructions_discover_all_skills():
    instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for slug in REQUIRED:
        assert f".github/skills/{slug}/SKILL.md" in instructions
    assert "independent" in instructions.lower()
    assert "signed" in instructions.lower()
    assert "cross-project" not in instructions or "No" in instructions


def test_skill_catalogue_contains_no_duplicate_slug_or_nonstandard_skill_files():
    directories = sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir())
    slugs = [path.name for path in directories]
    assert len(slugs) == len(set(slugs))
    assert set(REQUIRED).issubset(slugs)
    for folder in directories:
        assert _SKILL_NAME.fullmatch(folder.name)
        fields, _ = _read_skill(folder.name)
        assert fields["name"] == folder.name


def test_agent_onboarding_cannot_claim_pending_pr_is_released():
    _, onboarding = _read_skill("get-started")
    _, agent = _read_skill("governed-mcp-agent")
    assert "PR #90" in onboarding and "Check whether it is installed" in onboarding
    assert "PR #90" in agent and "Check" in agent
    assert "mcp-relay" in onboarding and "mcp-relay" in agent
    assert "signed" in agent.lower() and "DENY" in agent


def test_operator_and_release_skills_preserve_separation_and_approval():
    _, operator = _read_skill("operator-provisioning")
    _, release = _read_skill("release-verification")
    for phrase in ("Human approver", "Offline permit issuer", "Local operator"):
        assert phrase in operator
    assert "pre-opened file descriptor" in operator
    assert "APPROVED" in release
    assert "current commit SHA" in release
    assert "branch protection" in release
    assert "90%" in release
