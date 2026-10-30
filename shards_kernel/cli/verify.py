#!/usr/bin/env python3
"""Check internal consistency of an exported evidence bundle.

Reads ``ledger_entries`` and delegates the hash replay to
``shards_kernel.audit.replay.verify_evidence_bundle``. Replay recomputes each
entry hash from the entry content and compares ``prev_hash`` links and
``root_hash``.

``root_hash`` is taken from the bundle itself. A match shows only that the
bundle is internally consistent (integrity only). The bundle is not signed.

``replay_and_verify`` reports an empty entry list as consistent, and
``verify_evidence_bundle`` treats a missing ``ledger_entries`` key as ``[]``.
This command rejects those bundles before it delegates.

Usage:
    python -m shards_kernel.cli.verify evidence.json
    python -m shards_kernel.cli.verify --detailed evidence.json
    python -m shards_kernel.cli.verify --json evidence.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from shards_kernel.audit.replay import verify_evidence_bundle

# Export format has no schema field. An explicit schema name is not this format.
_SCHEMA_FIELDS = ("schema", "schema_version")
_STATUS_CONSISTENT = "internally consistent (integrity only)"
_STATUS_INCONSISTENT = "inconsistent"


@dataclass
class ConsistencyResult:
    """Outcome of an internal-consistency check."""

    internally_consistent: bool
    errors: list[str]
    entry_count: int
    delegated: bool
    bundle: Optional[dict[str, Any]] = None


def reject_before_replay(evidence: Any) -> Optional[str]:
    """Return a fail-closed reason, or None when replay may run.

    Call this before ``verify_evidence_bundle``. An empty or missing
    ``ledger_entries`` list must not be delegated: ``replay_and_verify``
    returns ``(True, [])`` for an empty entry list, and the bundle helper
    reads a missing key as ``[]``. A missing ``root_hash`` must not be
    delegated either, because replay skips the root comparison when that
    value is absent. The comparison uses the bundle's own ``root_hash``,
    so it shows internal consistency only.
    """
    if not isinstance(evidence, dict):
        return "unknown schema"
    if len(evidence) == 0:
        return "empty bundle"
    if any(field in evidence for field in _SCHEMA_FIELDS):
        return "unknown schema"
    # Canonical exports use ledger_entries. `entries` is not aliased: replay
    # does not read it, and a missing ledger_entries key would be delegated
    # as an empty list that replay reports as consistent.
    if "entries" in evidence:
        return "legacy entries key is not accepted"
    foreign = [
        key
        for key in evidence
        if key != "ledger_entries" and key.endswith("entries")
    ]
    if foreign:
        return f"unknown entries key: {foreign[0]}"
    if "ledger_entries" not in evidence:
        return "missing ledger_entries"
    entries = evidence["ledger_entries"]
    if not isinstance(entries, list):
        return "unknown entries key: ledger_entries"
    if len(entries) == 0:
        return "empty ledger_entries"
    if any(not isinstance(entry, dict) for entry in entries):
        return "malformed bundle"
    root_hash = evidence.get("root_hash")
    if not isinstance(root_hash, str) or root_hash.strip() == "":
        return "missing root_hash"
    return None


def _entry_count(evidence: Any) -> int:
    if isinstance(evidence, dict) and isinstance(evidence.get("ledger_entries"), list):
        return len(evidence["ledger_entries"])
    return 0


def _rejected(evidence: Any, reason: str) -> ConsistencyResult:
    bundle = evidence if isinstance(evidence, dict) else None
    return ConsistencyResult(
        internally_consistent=False,
        errors=[reason],
        entry_count=_entry_count(evidence),
        delegated=False,
        bundle=bundle,
    )


def verify_evidence(evidence: Any, detailed: bool = False) -> ConsistencyResult:
    """Check one bundle mapping for internal consistency.

    ``detailed`` is accepted so existing callers keep working. It does not
    change the check. The returned flag means the bundle is internally
    consistent, not that an outside party produced it.
    """
    del detailed  # formatting is the caller's job; the check is the same
    reason = reject_before_replay(evidence)
    if reason is not None:
        return _rejected(evidence, reason)

    replayed = verify_evidence_bundle(evidence)
    return ConsistencyResult(
        internally_consistent=replayed.is_valid,
        errors=list(replayed.errors),
        entry_count=_entry_count(evidence),
        delegated=True,
        bundle=evidence,
    )


def verify_evidence_file(filepath: str, detailed: bool = False) -> ConsistencyResult:
    """Load a bundle file and check internal consistency."""
    path = Path(filepath)
    if not path.exists():
        return ConsistencyResult(
            internally_consistent=False,
            errors=[f"file not found: {filepath}"],
            entry_count=0,
            delegated=False,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _rejected(None, f"malformed JSON: {exc}")
    except (OSError, UnicodeError) as exc:
        return _rejected(None, f"unable to read evidence file: {exc}")
    return verify_evidence(payload, detailed=detailed)


def format_report(result: ConsistencyResult, *, detailed: bool) -> str:
    """Render a text report. Success text states internal consistency only."""
    status = _STATUS_CONSISTENT if result.internally_consistent else _STATUS_INCONSISTENT
    lines = [
        "Shards-Kernel evidence bundle",
        f"status: {status}",
        f"entries: {result.entry_count}",
    ]
    bundle = result.bundle or {}
    root_hash = bundle.get("root_hash")
    if isinstance(root_hash, str) and root_hash.strip():
        lines.append(f"root_hash: {root_hash[:32]}")
    if result.errors:
        lines.append("reasons:")
        for error in result.errors:
            lines.append(f"- {error}")
    if detailed:
        entries = bundle.get("ledger_entries")
        if isinstance(entries, list):
            lines.append("ledger:")
            for index, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    lines.append(f"{index}. malformed entry")
                    continue
                digest = entry.get("entry_hash") or ""
                prefix = digest[:32] if isinstance(digest, str) else ""
                lines.append(
                    f"{index}. seq={entry.get('ledger_seq')} "
                    f"decision={entry.get('decision')} entry_hash={prefix}"
                )
    return "\n".join(lines) + "\n"


def format_json(result: ConsistencyResult) -> str:
    """Render a JSON summary. The status string is the same text report."""
    status = _STATUS_CONSISTENT if result.internally_consistent else _STATUS_INCONSISTENT
    return json.dumps(
        {
            "internally_consistent": result.internally_consistent,
            "status": status,
            "errors": result.errors,
            "entry_count": result.entry_count,
        },
        indent=2,
    )


def _emit(result: ConsistencyResult, *, detailed: bool, as_json: bool) -> None:
    print(format_report(result, detailed=detailed), end="")
    if as_json:
        print(format_json(result))


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns 0 only when the bundle is internally consistent."""
    parser = argparse.ArgumentParser(
        prog="shards_kernel.cli.verify",
        description=(
            "Check whether an exported evidence bundle is internally consistent "
            "(integrity only). root_hash is read from the bundle."
        ),
    )
    parser.add_argument(
        "evidence_file",
        help="Path to an evidence bundle JSON file",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show ledger entry fields",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also print a JSON summary",
    )
    args = parser.parse_args(argv)
    result = verify_evidence_file(args.evidence_file, detailed=args.detailed)
    _emit(result, detailed=args.detailed, as_json=args.json)
    return 0 if result.internally_consistent else 1


if __name__ == "__main__":
    sys.exit(main())
