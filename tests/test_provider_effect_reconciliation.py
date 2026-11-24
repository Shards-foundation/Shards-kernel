"""Read-only provider-effect/audit reconciliation regression tests."""

from __future__ import annotations

import json
import runpy
import sqlite3
import sys
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


def test_reconcile_covers_incident_classifications(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    journal = ProviderEffectJournal(str(journal_path))
    expected: dict[str, str] = {}

    # SUCCEEDED with no intent, and with an outcome that denies the effect.
    expected["s-no-intent"] = _journal_record(
        journal, "req-s-no-intent", "s" * 64, _params(61), SUCCEEDED
    )
    mismatch_params = _params(62)
    audit.intent("req-s-mismatch", "t" * 64, mismatch_params)
    audit.outcome("req-s-mismatch", "t" * 64, mismatch_params, allow=False)
    expected["s-mismatch"] = _journal_record(
        journal, "req-s-mismatch", "t" * 64, mismatch_params, SUCCEEDED
    )

    # NOT_APPLIED with no intent, no outcome, and an outcome that allows.
    expected["n-no-intent"] = _journal_record(
        journal, "req-n-no-intent", "u" * 64, _params(63), NOT_APPLIED
    )
    no_outcome_params = _params(64)
    audit.intent("req-n-no-outcome", "v" * 64, no_outcome_params)
    expected["n-no-outcome"] = _journal_record(
        journal, "req-n-no-outcome", "v" * 64, no_outcome_params, NOT_APPLIED
    )
    n_mismatch_params = _params(65)
    audit.intent("req-n-mismatch", "w" * 64, n_mismatch_params)
    audit.outcome("req-n-mismatch", "w" * 64, n_mismatch_params, allow=True)
    expected["n-mismatch"] = _journal_record(
        journal, "req-n-mismatch", "w" * 64, n_mismatch_params, NOT_APPLIED
    )

    report = rec.reconcile(audit_path, journal_path)

    by_operation = {record["operation_id"]: record for record in report["records"]}
    classifications = {
        suffix: by_operation[operation]["classification"] for suffix, operation in expected.items()
    }
    assert classifications == {
        "s-no-intent": rec.INCIDENT_INTENT_MISSING,
        "s-mismatch": rec.INCIDENT_OUTCOME_MISMATCH,
        "n-no-intent": rec.INCIDENT_INTENT_MISSING,
        "n-no-outcome": rec.INCIDENT_NOT_APPLIED_NO_OUTCOME,
        "n-mismatch": rec.INCIDENT_OUTCOME_MISMATCH,
    }
    assert report["status"] == "INCIDENT"


def test_reconcile_reports_attention_without_incidents(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    journal = ProviderEffectJournal(str(journal_path))

    unknown_params = _params(66)
    audit.intent("req-unknown", "x" * 64, unknown_params)
    _journal_record(journal, "req-unknown", "x" * 64, unknown_params, UNKNOWN)
    open_params = _params(67)
    audit.intent("req-open", "y" * 64, open_params)
    _journal_record(journal, "req-open", "y" * 64, open_params, INTENT)

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "ATTENTION"
    assert report["counts"] == {
        rec.QUARANTINED_UNKNOWN: 1,
        rec.OPEN_OPERATION: 1,
    }


def test_reconcile_flags_journal_record_with_invalid_binding(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    _Audit(audit_path).intent("req-valid", "a" * 64, _params(68))
    ProviderEffectJournal(str(journal_path))
    params = _params(69)
    connection = sqlite3.connect(str(journal_path))
    try:
        connection.execute(
            "INSERT INTO provider_effect_journal (operation_id, provider, resource, "
            "action, params_sha256, request_id, permit_id, state, attempts, "
            "created_ms, updated_ms, provider_ref, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "0" * 64,
                "github",
                RESOURCE,
                "add_label",
                compute_hash_dict(params),
                "x" * 501,
                "b" * 64,
                SUCCEEDED,
                1,
                1,
                1,
                "",
                "",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "INCIDENT"
    record = next(item for item in report["records"] if item["operation_id"] == "0" * 64)
    assert record["classification"] == rec.BINDING_MISMATCH


def test_reconcile_skips_audit_entries_with_invalid_binding_fields(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    audit = _Audit(audit_path)
    params = _params(70)
    audit.intent("req-complete", "c" * 64, params)
    audit.outcome("req-complete", "c" * 64, params, allow=True)
    journal = ProviderEffectJournal(str(journal_path))
    _journal_record(journal, "req-complete", "c" * 64, params, SUCCEEDED)

    audit.ledger.append(
        request_id="req-bad-permit",
        actor="agent-alice",
        intent="invalid permit digest",
        decision=Decision.ALLOW,
        state_from=KernelState.IDLE,
        state_to=KernelState.EXECUTING,
        ts_ms=audit._tick(),
        tool_name=TOOL_NAME,
        params=_params(71),
        audit_phase="intent",
        permit_digest="d" * 501,
    )
    audit.ledger.append(
        request_id=None,
        actor="agent-alice",
        intent="non-string request id",
        decision=Decision.ALLOW,
        state_from=KernelState.IDLE,
        state_to=KernelState.EXECUTING,
        ts_ms=audit._tick(),
    )

    report = rec.reconcile(audit_path, journal_path)

    assert report["status"] == "CLEAN"
    assert report["audit_only_incidents"] == []
    assert report["counts"] == {rec.COMPLETE_SUCCEEDED: 1}


def test_reconcile_rejects_relative_path_and_missing_tables(tmp_path):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)

    with pytest.raises(rec.ReconcileError, match="ABSOLUTE_SOURCE_PATH_REQUIRED"):
        rec.reconcile(Path("relative-audit.sqlite3"), journal_path)

    empty_audit = tmp_path / "empty-audit.sqlite3"
    sqlite3.connect(str(empty_audit)).close()
    with pytest.raises(rec.ReconcileError, match="AUDIT_TABLE_MISSING"):
        rec.reconcile(empty_audit, journal_path)

    empty_journal = tmp_path / "empty-journal.sqlite3"
    sqlite3.connect(str(empty_journal)).close()
    with pytest.raises(rec.ReconcileError, match="JOURNAL_TABLE_MISSING"):
        rec.reconcile(audit_path, empty_journal)


def test_reconcile_rejects_empty_ledger_and_unknown_kernel(tmp_path):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    SQLiteAuditStorage(str(audit_path))
    ProviderEffectJournal(str(journal_path))

    with pytest.raises(rec.ReconcileError, match="AUDIT_LEDGER_EMPTY"):
        rec.reconcile(audit_path, journal_path)

    _Audit(audit_path).intent("req-known", "e" * 64, _params(72))
    with pytest.raises(rec.ReconcileError, match="KERNEL_ID_NOT_FOUND"):
        rec.reconcile(audit_path, journal_path, kernel_id="unknown-kernel")


@pytest.mark.parametrize("payload", ["not-json", "[]"])
def test_reconcile_rejects_malformed_audit_payloads(tmp_path, payload):
    audit_path = tmp_path / "audit.sqlite3"
    journal_path = tmp_path / "journal.sqlite3"
    _Audit(audit_path).intent("req-valid", "f" * 64, _params(73))
    ProviderEffectJournal(str(journal_path))
    connection = sqlite3.connect(str(audit_path))
    try:
        connection.execute(
            "INSERT INTO audit_entries (kernel_id, ledger_seq, entry_hash, "
            "prev_hash, ts_ms, request_id, actor, intent, decision, "
            "state_from, state_to, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                KERNEL_ID,
                99,
                "hash",
                "prev",
                1,
                "request",
                "actor",
                "intent",
                "ALLOW",
                "IDLE",
                "EXECUTING",
                payload,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(rec.ReconcileError, match="AUDIT_ROW_MALFORMED"):
        rec.reconcile(audit_path, journal_path)


def test_module_entrypoint_exits_with_incident_code(tmp_path, monkeypatch, capsys):
    audit_path, journal_path, _operations = _build_mixed(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile_provider_effects.py",
            "--audit-db",
            str(audit_path),
            "--journal-db",
            str(journal_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "ops"
            / "reconcile_provider_effects.py"
        )
        runpy.run_path(str(script), run_name="__main__")

    assert excinfo.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INCIDENT"
