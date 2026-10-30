#!/usr/bin/env python3
"""Reject a coverage report whose governance modules fall below the branch floor.

Reads coverage.py JSON (pytest-cov ``--cov-report=json``). Branch percentage is
``covered_branches / num_branches``. File summaries do not always fill
``percent_covered_branches``, so this script computes the ratio itself.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Governance-critical modules. Raise this floor; do not lower it to go green.
FLOOR = 90.0
MODULES = (
    "shards_kernel/execution/dispatcher.py",
    "shards_kernel/common/validate.py",
    "shards_kernel/jurisdiction/rules.py",
    "shards_kernel/audit/ledger.py",
    "shards_kernel/audit/replay.py",
    "shards_kernel/permits.py",
    "shards_kernel/variants/base.py",
)


def branch_percent(summary: dict) -> float:
    """Return the branch coverage percentage for one file summary."""
    total = summary.get("num_branches") or 0
    covered = summary.get("covered_branches") or 0
    if total == 0:
        return 100.0
    return 100.0 * covered / total


def main() -> int:
    """Check each governance module and return a non-zero status on failure."""
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json")
    report = json.loads(path.read_text(encoding="utf-8"))
    files = report["files"]
    failed = False
    for module in MODULES:
        info = files.get(module)
        if info is None:
            print(f"MISSING {module}")
            failed = True
            continue
        summary = info["summary"]
        percent = branch_percent(summary)
        status = "OK" if percent + 1e-9 >= FLOOR else "FAIL"
        if status == "FAIL":
            failed = True
        print(
            f"{status} {module}: branch {percent:.2f}% "
            f"({summary.get('covered_branches')}/{summary.get('num_branches')})"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
