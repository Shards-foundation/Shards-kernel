"""Deterministic, offline GitHub issue-intake summary.

Reads the event JSON as data, never interpolates issue text into a shell
command or asks an LLM to follow untrusted issue instructions.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def _safe_text(value: Any, max_length: int) -> str:
    if not isinstance(value, str):
        return ""
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    value = re.sub(r"\s+", " ", value).strip()[:max_length]
    # Avoid generating notifications from copied @mentions in public issues.
    return value.replace("@", "@\u200b")


def summarize_issue(event: dict[str, Any]) -> str:
    """Return a bounded triage note with an excerpt, not an AI judgement."""
    issue = event.get("issue") or {}
    if not isinstance(issue, dict):
        issue = {}
    title = _safe_text(issue.get("title"), 180)
    raw = issue.get("body") or ""
    if not isinstance(raw, str):
        raw = ""
    raw = re.sub(r"(?s)```.*?```", "", raw)
    raw = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)
    candidate_lines = [
        line.strip(" -#*\t ")
        for line in raw.splitlines()
        if line.strip() and not re.match(r"^\s*[-*]?\s*\[[ xX]\]", line)
    ]
    excerpt = next(
        (line for line in candidate_lines if line and not line.startswith("|")),
        "No substantive description provided",
    )
    priority_match = re.search(r"\b(P[0-3])\b", title, flags=re.IGNORECASE)
    priority = priority_match.group(1).upper() if priority_match else "Unspecified"

    return (
        "### Automated issue intake (deterministic)\n\n"
        f"**Reported issue:** {_safe_text(title, 180) or 'Untitled'}\n\n"
        f"**Priority indicated by title:** {priority}\n\n"
        f"**Opening description:** {_safe_text(excerpt, 320)}\n\n"
        "This is an automatically extracted overview, **not** an AI review, "
        "security judgement or approval. A maintainer must verify the issue, "
        "scope and evidence before assigning priority or implementing changes.\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    event = json.loads(args.event.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ValueError("GitHub event payload must be an object")
    args.output.write_text(summarize_issue(event), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
