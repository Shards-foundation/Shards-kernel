"""Read-only reconciliation of provider effects against the audit hash chain.

This tool correlates the durable provider-effect journal
(``provider_effect_journal``) with the kernel's hash-chained audit ledger
(``audit_entries``) for the same request, operation and signed permit.

It is deliberately narrow:

* both SQLite databases are opened with ``mode=ro`` and ``query_only``;
* it never inserts, updates or deletes a row, and never fabricates an audit
  outcome;
* it never calls GitHub, retries a provider effect or removes a label;
* it reports a bounded classification and exits non-zero on an incident.

The critical case is a journal ``SUCCEEDED`` record whose matching audit
intent exists but whose audit outcome is absent. That is **not** complete
evidence that the effect was authorised and completed end-to-end, even though
the provider journal says the effect was applied. An operator must reconcile
the external provider state (for example, read the label in GitHub) before
recording an incident decision outside the signed chain.

Examples:
    python scripts/ops/reconcile_provider_effects.py \
        --audit-db /var/lib/shards-kernel/github-operator/audit.sqlite3 \
        --journal-db /var/lib/shards-kernel/github-operator/provider-journal.sqlite3

Exit codes: ``0`` clean, ``2`` incident or attention required, ``1`` tool error.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path
from typing import Any, Optional, cast
from urllib.parse import quote

from shards_kernel.audit.replay import replay_and_verify
from shards_kernel.providers.github_issue_label import (
    TOOL_NAME,
    ProviderValidationError,
    derive_operation_id,
)

PROVIDER = "github"
ACTION = "add_label"
JOURNAL_TABLE = "provider_effect_journal"
AUDIT_TABLE = "audit_entries"

SUCCEEDED = "SUCCEEDED"
NOT_APPLIED = "NOT_APPLIED"
UNKNOWN = "UNKNOWN"
INTENT = "INTENT"
DISPATCHED = "DISPATCHED"
KNOWN_STATES = frozenset({SUCCEEDED, NOT_APPLIED, UNKNOWN, INTENT, DISPATCHED})

COMPLETE_SUCCEEDED = "COMPLETE_SUCCEEDED"
COMPLETE_NOT_APPLIED = "COMPLETE_NOT_APPLIED"
INCIDENT_EFFECT_APPLIED_NO_OUTCOME = "INCIDENT_EFFECT_APPLIED_NO_OUTCOME"
INCIDENT_NOT_APPLIED_NO_OUTCOME = "INCIDENT_NOT_APPLIED_NO_OUTCOME"
INCIDENT_OUTCOME_MISMATCH = "INCIDENT_OUTCOME_MISMATCH"
INCIDENT_INTENT_MISSING = "INCIDENT_INTENT_MISSING"
INCIDENT_JOURNAL_RECORD_MISSING = "INCIDENT_JOURNAL_RECORD_MISSING"
QUARANTINED_UNKNOWN = "QUARANTINED_UNKNOWN"
OPEN_OPERATION = "OPEN_OPERATION"
BINDING_MISMATCH = "BINDING_MISMATCH"

_INCIDENT = frozenset(
    {
        INCIDENT_EFFECT_APPLIED_NO_OUTCOME,
        INCIDENT_NOT_APPLIED_NO_OUTCOME,
        INCIDENT_OUTCOME_MISMATCH,
        INCIDENT_INTENT_MISSING,
        INCIDENT_JOURNAL_RECORD_MISSING,
        BINDING_MISMATCH,
    }
)
_ATTENTION = frozenset({QUARANTINED_UNKNOWN, OPEN_OPERATION})


class ReconcileError(Exception):
    """A bounded, path-free reconciliation failure."""


def _validate_source(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ReconcileError("ABSOLUTE_SOURCE_PATH_REQUIRED")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReconcileError("SOURCE_UNAVAILABLE") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReconcileError("SOURCE_MUST_BE_REGULAR_FILE")
    return path


def _readonly_uri(path: Path) -> str:
    return "file:" + quote(str(path), safe="/") + "?mode=ro"


def _connect_readonly(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(_readonly_uri(path), uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection


def _require_table(connection: sqlite3.Connection, table: str, code: str) -> None:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if row is None:
        raise ReconcileError(code)


def _load_journal(path: Path) -> list[dict[str, Any]]:
    with closing(_connect_readonly(path)) as connection:
        _require_table(connection, JOURNAL_TABLE, "JOURNAL_TABLE_MISSING")
        rows = connection.execute(
            """
            SELECT operation_id, provider, resource, action, params_sha256,
                   request_id, permit_id, state, attempts, created_ms,
                   updated_ms, provider_ref, detail
            FROM provider_effect_journal
            ORDER BY created_ms ASC, operation_id ASC
            """
        ).fetchall()
    return [
        {
            "operation_id": str(row[0]),
            "provider": str(row[1]),
            "resource": str(row[2]),
            "action": str(row[3]),
            "params_sha256": str(row[4]),
            "request_id": str(row[5]),
            "permit_id": str(row[6]),
            "state": str(row[7]),
            "attempts": int(row[8]),
            "created_ms": int(row[9]),
            "updated_ms": int(row[10]),
            "provider_ref": str(row[11]),
            "detail": str(row[12]),
        }
        for row in rows
    ]


def _load_audit(path: Path, kernel_id: Optional[str]) -> tuple[str, list[dict[str, Any]], bool]:
    with closing(_connect_readonly(path)) as connection:
        _require_table(connection, AUDIT_TABLE, "AUDIT_TABLE_MISSING")
        kernel_rows = connection.execute(
            "SELECT DISTINCT kernel_id FROM audit_entries ORDER BY kernel_id ASC"
        ).fetchall()
        available = [str(row[0]) for row in kernel_rows]
        if not available:
            raise ReconcileError("AUDIT_LEDGER_EMPTY")
        if kernel_id is None:
            if len(available) != 1:
                raise ReconcileError("KERNEL_ID_REQUIRED")
            kernel_id = available[0]
        elif kernel_id not in available:
            raise ReconcileError("KERNEL_ID_NOT_FOUND")
        rows = connection.execute(
            """
            SELECT payload_json FROM audit_entries
            WHERE kernel_id = ?
            ORDER BY ledger_seq ASC
            """,
            (kernel_id,),
        ).fetchall()

    entries: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise ReconcileError("AUDIT_ROW_MALFORMED") from exc
        if not isinstance(payload, dict):
            raise ReconcileError("AUDIT_ROW_MALFORMED")
        entries.append(payload)

    expected_root = str(entries[-1].get("entry_hash") or "")
    verified, _errors = replay_and_verify(entries, expected_root_hash=expected_root)
    if not verified:
        raise ReconcileError("AUDIT_CHAIN_INVALID")
    return cast(str, kernel_id), entries, True


def _matches(
    entries: list[dict[str, Any]],
    phase: str,
    permit_id: str,
    params_hash: str,
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in entries
        if entry.get("audit_phase") == phase
        and entry.get("tool_name") == TOOL_NAME
        and entry.get("permit_digest") == permit_id
        and entry.get("params_hash") == params_hash
    ]


def _expected_operation_id(record: dict[str, Any]) -> Optional[str]:
    try:
        return derive_operation_id(
            request_id=record["request_id"],
            permit_id=record["permit_id"],
            params_sha256=record["params_sha256"],
        )
    except (ProviderValidationError, KeyError, TypeError):
        return None


def _classify(
    record: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    intent = _matches(entries, "intent", record["permit_id"], record["params_sha256"])
    outcome = _matches(entries, "outcome", record["permit_id"], record["params_sha256"])
    state = record["state"]

    if (
        record["provider"] != PROVIDER
        or record["action"] != ACTION
        or _expected_operation_id(record) != record["operation_id"]
        or state not in KNOWN_STATES
    ):
        return BINDING_MISMATCH, intent, outcome

    if state == SUCCEEDED:
        if not intent:
            return INCIDENT_INTENT_MISSING, intent, outcome
        if not outcome:
            return INCIDENT_EFFECT_APPLIED_NO_OUTCOME, intent, outcome
        if outcome[0].get("decision") == "ALLOW" and not outcome[0].get("error"):
            return COMPLETE_SUCCEEDED, intent, outcome
        return INCIDENT_OUTCOME_MISMATCH, intent, outcome

    if state == NOT_APPLIED:
        if not intent:
            return INCIDENT_INTENT_MISSING, intent, outcome
        if not outcome:
            return INCIDENT_NOT_APPLIED_NO_OUTCOME, intent, outcome
        if outcome[0].get("decision") == "DENY":
            return COMPLETE_NOT_APPLIED, intent, outcome
        return INCIDENT_OUTCOME_MISMATCH, intent, outcome

    if state == UNKNOWN:
        return QUARANTINED_UNKNOWN, intent, outcome
    return OPEN_OPERATION, intent, outcome


def _audit_only_incidents(
    entries: list[dict[str, Any]], journal_ids: set[str]
) -> list[dict[str, Any]]:
    """Audit provider intents with no journal row imply a lost/mismatched journal."""
    incidents: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("audit_phase") != "intent" or entry.get("tool_name") != TOOL_NAME:
            continue
        try:
            operation_id = derive_operation_id(
                request_id=entry.get("request_id"),
                permit_id=entry.get("permit_digest"),
                params_sha256=entry.get("params_hash"),
            )
        except ProviderValidationError:
            continue
        if operation_id in journal_ids:
            continue
        incidents.append(
            {
                "operation_id": operation_id,
                "request_id": entry.get("request_id"),
                "permit_id": entry.get("permit_digest"),
                "audit_phase": "intent",
                "classification": INCIDENT_JOURNAL_RECORD_MISSING,
            }
        )
    return incidents


def reconcile(
    audit_db: Path,
    journal_db: Path,
    *,
    kernel_id: Optional[str] = None,
) -> dict[str, Any]:
    """Correlate one audit ledger and one provider journal, read-only."""
    audit_path = _validate_source(Path(audit_db))
    journal_path = _validate_source(Path(journal_db))

    kernel_id, audit_entries, chain_verified = _load_audit(audit_path, kernel_id)
    journal_records = _load_journal(journal_path)

    by_request: dict[str, list[dict[str, Any]]] = {}
    for entry in audit_entries:
        request_id = entry.get("request_id")
        if isinstance(request_id, str):
            by_request.setdefault(request_id, []).append(entry)

    records: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for record in journal_records:
        classification, intent, outcome = _classify(
            record, by_request.get(record["request_id"], [])
        )
        counts[classification] = counts.get(classification, 0) + 1
        records.append(
            {
                "operation_id": record["operation_id"],
                "request_id": record["request_id"],
                "permit_id": record["permit_id"],
                "resource": record["resource"],
                "action": record["action"],
                "state": record["state"],
                "provider_ref": record["provider_ref"],
                "detail": record["detail"],
                "audit_intent": bool(intent),
                "audit_outcome": bool(outcome),
                "outcome_decision": outcome[0].get("decision") if outcome else None,
                "outcome_error": outcome[0].get("error") if outcome else None,
                "classification": classification,
            }
        )

    audit_only = _audit_only_incidents(
        audit_entries, {record["operation_id"] for record in journal_records}
    )
    for incident in audit_only:
        counts[INCIDENT_JOURNAL_RECORD_MISSING] = counts.get(INCIDENT_JOURNAL_RECORD_MISSING, 0) + 1

    if audit_only or any(key in _INCIDENT for key in counts):
        status = "INCIDENT"
    elif any(key in _ATTENTION for key in counts):
        status = "ATTENTION"
    else:
        status = "CLEAN"

    halt_entries = sum(1 for entry in audit_entries if entry.get("audit_phase") == "halt")
    return {
        "status": status,
        "tool": TOOL_NAME,
        "kernel_id": kernel_id,
        "audit_chain_verified": chain_verified,
        "journal_records": len(journal_records),
        "audit_entries": len(audit_entries),
        "audit_halt_entries": halt_entries,
        "counts": dict(sorted(counts.items())),
        "records": records,
        "audit_only_incidents": audit_only,
        "scope": (
            "single-host read-only correlation; no provider call, no repair, "
            "no retry and no fabricated audit entry"
        ),
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--journal-db", type=Path, required=True)
    parser.add_argument(
        "--kernel-id",
        default=None,
        help="Audit kernel_id; required only when the audit DB holds more than one",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = reconcile(args.audit_db, args.journal_db, kernel_id=args.kernel_id)
    except ReconcileError as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "CLEAN" else 2


if __name__ == "__main__":
    sys.exit(main())
