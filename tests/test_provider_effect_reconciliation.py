"""Read-only provider-effect/audit reconciliation regression tests."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from implementations.storage import SQLiteAuditStorage
from scripts.ops import reconcile_provider_effects as rec
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.common.hashing import compute_hash_dict
from shards_kernel.common.types import Decision, KernelState
from shards_kernel.providers.github_issue_label import TOOL_NAME, derive_operation_id
from shards_kernel.providers.journal import (
    INTENT,
    NOT_APPLIED,
    SUCCEEDED,
    UNKNOWN,
    ProviderEffectJournal,
)

KERNEL_ID = "github-operator"
RESOURCE = "octo/demo"


def _params(issue: int) -> dict:
    return {"issue_number": issue, "label": "triage"}


def _operation_id(request_id: str, permit_id: str, params: dict) -> str:
    return derive_operation_id(
        request_id=request_id,
        permit_id=permit_id,
        params_sha256=compute_hash_dict(params),
    )


class _Audit:
    def __init__(self, path: Path, kernel_id: str = KERNEL_ID) -> None:
        self.ledger = AuditLedger(kernel_id, "strict", storage=SQLiteAuditStorage(str(path)))
        self.ts = 1_000

    def _tick(self) -> int:
        self.ts += 1
        return self.ts

    def intent(self, request_id: str, permit_id: str, params: dict) -> None:
        self.ledger.append(
            request_id=request_id,
            actor="agent-alice",
            intent="add one allowlisted label",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE,
            state_to=KernelState.EXECUTING,
            ts_ms=self._tick(),
            tool_name=TOOL_NAME,
            params=params,
            audit_phase="intent",
            permit_digest=permit_id,
            permit_verification="INTENT",
            permit_nonce="nonce-" + request_id,
            permit_issuer="operator",
            permit_subject="agent-alice",
            permit_max_executions=1,
        )

    def outcome(self, request_id: str, permit_id: str, params: dict, *, allow: bool) -> None:
        self.ledger.append(
            request_id=request_id,
            actor="agent-alice",
            intent="add one allowlisted label",
            decision=Decision.ALLOW if allow else Decision.DENY,
            state_from=KernelState.EXECUTING,
            state_to=KernelState.COMPLETED,
            ts_ms=self._tick(),
            tool_name=TOOL_NAME,
            params=params,
            error=None if allow else "PROVIDER_NOT_APPLIED: rejected",
            audit_phase="outcome",
            permit_digest=permit_id,
            permit_verification="OUTCOME",
            permit_nonce="nonce-" + request_id,
            permit_issuer="operator",
            permit_subject="agent-alice",
            permit_max_executions=1,
        )

    def halt(self) -> None:
        self.ledger.append(
            request_id="HALT",
            actor="SYSTEM",
            intent="Unhandled exception during request processing",
            decision=Decision.HALT,
            state_from=KernelState.AUDITING,
            state_to=KernelState.HALTED,
            ts_ms=self._tick(),
            error="Unhandled exception during request processing",
            audit_phase="halt",
        )


def _journal_record(
    journal: ProviderEffectJournal,
    request_id: str,
    permit_id: str,
    params: dict,
    state: str,
    *,
    operation_id: str | None = None,
) -> str:
    params_sha = compute_hash_dict(params)
    operation = operation_id or derive_operation_id(
        request_id=request_id, permit_id=permit_id, params_sha256=params_sha
    )
    journal.reserve(
        operation_id=operation,
        provider="github",
        resource=RESOURCE,
        action="add_label",
        params_sha256=params_sha,
        request_id=request_id,
        permit_id=permit_id,
    )
    if state == INTENT:
        return operation
    journal.record_outcome(
        operation,
        state,
        provider_ref=f"github:{RESOURCE}#{params['issue_number']}:{params['label']}",
        detail="" if state == SUCCEEDED else "provider rejected",
    )
    return operation


def _build_mixed(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    journal = ProviderEffectJournal(str(journal_path))
    operations: dict[str, str] = {}

    cases = [
        ("a", 7, SUCCEEDED, "outcome_allow"),
        ("b", 8, SUCCEEDED, "intent_only"),
        ("c", 9, NOT_APPLIED, "outcome_deny"),
        ("d", 10, UNKNOWN, "outcome_deny"),
        ("e", 11, INTENT, "intent_only"),
    ]
    for suffix, issue, state, shape in cases:
        request_id = "req-" + suffix
        permit_id = suffix * 64
        params = _params(issue)
        audit.intent(request_id, permit_id, params)
        if shape == "outcome_allow":
            audit.outcome(request_id, permit_id, params, allow=True)
        elif shape == "outcome_deny":
            audit.outcome(request_id, permit_id, params, allow=False)
        operations[suffix] = _journal_record(journal, request_id, permit_id, params, state)

    # Two operations share one request_id but differ by permit/params. A join
    # that only compares request_id would hide the missing outcome for "f".
    shared_params = _params(12)
    audit.intent("req-shared", "f" * 64, shared_params)
    operations["f"] = _journal_record(journal, "req-shared", "f" * 64, shared_params, SUCCEEDED)
    complete_params = _params(13)
    audit.intent("req-shared", "g" * 64, complete_params)
    audit.outcome("req-shared", "g" * 64, complete_params, allow=True)
    operations["g"] = _journal_record(journal, "req-shared", "g" * 64, complete_params, SUCCEEDED)

    audit.halt()
    return audit_path, journal_path, operations


def test_reconcile_classifies_each_operation_without_tautology(tmp_path):
    audit_path, journal_path, operations = _build_mixed(tmp_path)

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "INCIDENT"
    assert report["audit_chain_verified"] is True
    assert report["journal_records"] == 7
    assert report["audit_halt_entries"] == 1
    by_operation = {record["operation_id"]: record for record in report["records"]}
    assert len(by_operation) == 7

    expected = {
        "a": rec.COMPLETE_SUCCEEDED,
        "b": rec.INCIDENT_EFFECT_APPLIED_NO_OUTCOME,
        "c": rec.COMPLETE_NOT_APPLIED,
        "d": rec.QUARANTINED_UNKNOWN,
        "e": rec.OPEN_OPERATION,
        "f": rec.INCIDENT_EFFECT_APPLIED_NO_OUTCOME,
        "g": rec.COMPLETE_SUCCEEDED,
    }
    for suffix, classification in expected.items():
        record = by_operation[operations[suffix]]
        assert record["classification"] == classification, suffix
        assert record["audit_intent"] is True

    assert by_operation[operations["b"]]["audit_outcome"] is False
    assert by_operation[operations["f"]]["audit_outcome"] is False
    assert by_operation[operations["g"]]["audit_outcome"] is True
    assert report["counts"][rec.INCIDENT_EFFECT_APPLIED_NO_OUTCOME] == 2
    assert report["counts"][rec.COMPLETE_SUCCEEDED] == 2


def test_reconcile_never_writes_and_opens_read_only(tmp_path):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)

    def fingerprint(path: Path) -> tuple[int, int, int, str]:
        info = path.stat()
        connection = sqlite3.connect(str(path))
        try:
            rows = connection.execute(
                "SELECT * FROM audit_entries ORDER BY ledger_seq"
                if path == audit_path
                else "SELECT * FROM provider_effect_journal ORDER BY operation_id"
            ).fetchall()
        finally:
            connection.close()
        return info.st_ino, info.st_mtime_ns, info.st_size, repr(rows)

    before = (fingerprint(audit_path), fingerprint(journal_path))
    rec.reconcile(audit_path, journal_path)
    after = (fingerprint(audit_path), fingerprint(journal_path))
    assert before == after

    with closing(rec._connect_readonly(audit_path)) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute(
                "INSERT INTO audit_entries (kernel_id, ledger_seq, entry_hash, "
                "prev_hash, ts_ms, request_id, actor, intent, decision, "
                "state_from, state_to, payload_json) "
                "VALUES ('x', 99, 'h', 'p', 1, 'r', 'a', 'i', 'ALLOW', "
                "'IDLE', 'COMPLETED', '{}')"
            )
    with closing(rec._connect_readonly(journal_path)) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("UPDATE provider_effect_journal SET state = 'SUCCEEDED' WHERE 0")


def test_reconcile_reports_audit_intent_without_journal_record(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    audit.intent("req-lost", "z" * 64, _params(21))
    ProviderEffectJournal(str(journal_path))

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "INCIDENT"
    assert report["journal_records"] == 0
    assert len(report["audit_only_incidents"]) == 1
    incident = report["audit_only_incidents"][0]
    assert incident["classification"] == rec.INCIDENT_JOURNAL_RECORD_MISSING
    assert incident["request_id"] == "req-lost"


def test_reconcile_flags_operation_binding_mismatch(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    journal = ProviderEffectJournal(str(journal_path))
    params = _params(31)
    audit.intent("req-binding", "y" * 64, params)
    audit.outcome("req-binding", "y" * 64, params, allow=True)
    _journal_record(
        journal,
        "req-binding",
        "y" * 64,
        params,
        SUCCEEDED,
        operation_id="0" * 64,
    )

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "INCIDENT"
    assert report["records"][0]["classification"] == rec.BINDING_MISMATCH


def test_reconcile_rejects_tampered_audit_chain(tmp_path):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)
    connection = sqlite3.connect(str(audit_path))
    try:
        row = connection.execute(
            "SELECT kernel_id, ledger_seq, payload_json FROM audit_entries "
            "ORDER BY ledger_seq LIMIT 1"
        ).fetchone()
        payload = json.loads(row[2])
        payload["intent"] = "tampered after commit"
        connection.execute(
            "UPDATE audit_entries SET payload_json = ? WHERE kernel_id = ? AND ledger_seq = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), row[0], row[1]),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(rec.ReconcileError, match="AUDIT_CHAIN_INVALID"):
        rec.reconcile(audit_path, journal_path)


def test_cli_exit_codes_and_bounded_errors(tmp_path, capsys):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)
    assert rec.main(["--audit-db", str(audit_path), "--journal-db", str(journal_path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "INCIDENT"

    clean_audit = tmp_path / "clean-audit.sqlite3"
    clean_journal = tmp_path / "clean-journal.sqlite3"
    audit = _Audit(clean_audit)
    journal = ProviderEffectJournal(str(clean_journal))
    params = _params(41)
    audit.intent("req-clean", "c" * 64, params)
    audit.outcome("req-clean", "c" * 64, params, allow=True)
    _journal_record(journal, "req-clean", "c" * 64, params, SUCCEEDED)
    assert rec.main(["--audit-db", str(clean_audit), "--journal-db", str(clean_journal)]) == 0
    clean_output = json.loads(capsys.readouterr().out)
    assert clean_output["status"] == "CLEAN"

    missing = tmp_path / "does-not-exist.sqlite3"
    assert rec.main(["--audit-db", str(missing), "--journal-db", str(clean_journal)]) == 1
    error_output = capsys.readouterr().out
    assert json.loads(error_output) == {
        "status": "ERROR",
        "error": "SOURCE_UNAVAILABLE",
    }
    assert str(missing) not in error_output


def test_reconcile_requires_kernel_id_for_multi_kernel_audit_db(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    first = _Audit(audit_path)
    first.intent("req-first", "1" * 64, _params(51))
    second = _Audit(audit_path, "other-kernel")
    second.intent("req-second", "2" * 64, _params(52))
    ProviderEffectJournal(str(journal_path))

    with pytest.raises(rec.ReconcileError, match="KERNEL_ID_REQUIRED"):
        rec.reconcile(audit_path, journal_path)

    report = rec.reconcile(audit_path, journal_path, kernel_id=KERNEL_ID)
    assert report["kernel_id"] == KERNEL_ID
    assert report["audit_entries"] == 1


def test_reconcile_rejects_symlink_source(tmp_path):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)
    link = tmp_path / "audit-link.sqlite3"
    link.symlink_to(audit_path)

    with pytest.raises(rec.ReconcileError, match="SOURCE_MUST_BE_REGULAR_FILE"):
        rec.reconcile(link, journal_path)
