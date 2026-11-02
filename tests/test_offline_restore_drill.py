"""Offline restore-drill regression tests using actual persistent SQLite ledgers."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from implementations.storage import SQLiteAuditStorage
from scripts.ops.verify_sqlite_restore import DrillError, main, verify_restore
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.common.types import Decision, KernelState


def _audit(tmp_path, *, kernel_id="restore-example", phases=("intent", "outcome")):
    database = tmp_path / "audit.sqlite3"
    ledger = AuditLedger(
        kernel_id, "strict", storage=SQLiteAuditStorage(str(database))
    )
    for number, phase in enumerate(phases):
        ledger.append(
            request_id="approved-request",
            actor="agent-alpha",
            intent="offline restore test",
            decision=Decision.ALLOW,
            state_from=KernelState.IDLE if phase == "intent" else KernelState.EXECUTING,
            state_to=KernelState.EXECUTING if phase == "intent" else KernelState.COMPLETED,
            ts_ms=1_000 + number,
            tool_name="echo",
            params={"text": "redacted in report"},
            audit_phase=phase,
        )
    return database, ledger.root_hash


def _must_reject(path: Path, expected: str, **kwargs):
    with pytest.raises(DrillError, match=expected):
        verify_restore(source=path, kernel_id="restore-example", **kwargs)


def test_restore_drill_uses_actual_sqlite_snapshot_and_chain(tmp_path):
    database, root = _audit(tmp_path)
    result = verify_restore(
        source=database, kernel_id="restore-example", expected_root=root,
        min_entries=2,
    )
    assert result.root_hash == root
    assert result.entry_count == 2
    assert result.pending_intents == 0
    assert result.policy_revision is None
    assert result.external_root_compared is True
    assert result.to_dict()["status"] == "LOCAL_RESTORE_VERIFIED"
    assert "redacted in report" not in json.dumps(result.to_dict())
    # Restore rehearsal cannot overwrite or remove the original audit store.
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone() == (2,)


def test_restore_drill_readonly_snapshot_includes_uncheckpointed_wal(tmp_path):
    database, root = _audit(tmp_path)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        connection.execute(
            "CREATE TABLE IF NOT EXISTS operator_policy_checkpoint ("
            "kernel_id TEXT PRIMARY KEY, revision INTEGER, digest TEXT)"
        )
        connection.execute(
            "INSERT INTO operator_policy_checkpoint VALUES (?, ?, ?)",
            ("restore-example", 4, "a" * 64),
        )
        connection.commit()
        # Keep a WAL-aware connection open while the online SQLite backup runs.
        result = verify_restore(
            source=database, kernel_id="restore-example", expected_root=root,
            min_policy_revision=4,
        )
    assert result.policy_revision == 4


def test_rejects_corruption_even_when_stored_row_hash_looks_valid(tmp_path):
    database, _ = _audit(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_entries SET payload_json = "
            "replace(payload_json, 'approved-request', 'forged-request') "
            "WHERE ledger_seq = 0"
        )
    _must_reject(database, "SNAPSHOT_OR_REPLAY_REJECTED")


def test_rejects_unreconciled_execution_intent(tmp_path):
    database, _ = _audit(tmp_path, phases=("intent",))
    _must_reject(database, "UNRECONCILED_EXECUTION_INTENTS")


@pytest.mark.parametrize(
    ("expected", "kwargs"),
    [
        ("EXTERNAL_ROOT_MISMATCH", {"expected_root": "0" * 64}),
        ("INVALID_EXPECTED_ROOT", {"expected_root": "not-a-root"}),
        ("MINIMUM_AUDIT_ENTRIES_NOT_MET", {"min_entries": 3}),
        ("POLICY_REVISION_BELOW_TRUSTED_FLOOR", {"min_policy_revision": 1}),
        ("INVALID_MIN_ENTRIES", {"min_entries": 0}),
        ("INVALID_MIN_POLICY_REVISION", {"min_policy_revision": 0}),
    ],
)
def test_rejects_inadequate_evidence_and_invalid_anchors(tmp_path, expected, kwargs):
    database, _ = _audit(tmp_path)
    _must_reject(database, expected, **kwargs)


def test_rejects_wrong_kernel_id_and_missing_or_symlink_sources(tmp_path):
    database, _ = _audit(tmp_path)
    with pytest.raises(DrillError, match="KERNEL_METADATA_MISSING"):
        verify_restore(source=database, kernel_id="not-enrolled")
    with pytest.raises(DrillError, match="INVALID_KERNEL_ID"):
        verify_restore(source=database, kernel_id="../invalid")
    _must_reject(tmp_path / "missing.sqlite3", "SOURCE_UNAVAILABLE")
    _must_reject(Path("relative.sqlite3"), "ABSOLUTE_SOURCE_PATH_REQUIRED")
    link = tmp_path / "alias.sqlite3"
    link.symlink_to(database)
    _must_reject(link, "SOURCE_MUST_BE_REGULAR_FILE")


def test_rejects_truncated_and_unrecognised_database(tmp_path):
    database = tmp_path / "invalid.sqlite3"
    database.write_bytes(b"this is not a SQLite database")
    _must_reject(database, "SNAPSHOT_OR_REPLAY_REJECTED")
    database.unlink()
    database.touch()
    _must_reject(database, "SNAPSHOT_OR_REPLAY_REJECTED")


def test_rejects_empty_audit_ledger(tmp_path):
    database = tmp_path / "audit.sqlite3"
    SQLiteAuditStorage(str(database)).bind_kernel("restore-example", "strict")
    _must_reject(database, "MINIMUM_AUDIT_ENTRIES_NOT_MET")


def test_rejects_invalid_checkpoint_revision(tmp_path):
    database, _ = _audit(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE operator_policy_checkpoint "
            "(kernel_id TEXT PRIMARY KEY, revision TEXT, digest TEXT)"
        )
        connection.execute(
            "INSERT INTO operator_policy_checkpoint VALUES (?, ?, ?)",
            ("restore-example", "not-a-number", "broken"),
        )
    _must_reject(database, "INVALID_POLICY_CHECKPOINT")


def test_detects_replaced_source_during_backup(tmp_path, monkeypatch):
    import scripts.ops.verify_sqlite_restore as module

    database, _ = _audit(tmp_path)
    original = module._source_identity
    calls = [0]

    def swapping(path):
        calls[0] += 1
        identity = original(path)
        return identity if calls[0] == 1 else (identity[0], identity[1] + 1)

    monkeypatch.setattr(module, "_source_identity", swapping)
    _must_reject(database, "SOURCE_CHANGED_DURING_SNAPSHOT")


def test_cli_outputs_bounded_json_and_never_leaks_audit_details(tmp_path, capsys):
    database, root = _audit(tmp_path)
    assert main([
        "--source", str(database), "--kernel-id", "restore-example",
        "--expected-root", root, "--min-entries", "2",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "LOCAL_RESTORE_VERIFIED"
    assert report["external_root_compared"] is True
    assert str(database) not in json.dumps(report)
    assert main([
        "--source", str(database), "--kernel-id", "restore-example",
        "--expected-root", "0" * 64,
    ]) == 2
    failure = json.loads(capsys.readouterr().out)
    assert failure == {"status": "REJECTED", "reason": "EXTERNAL_ROOT_MISMATCH"}
    assert str(database) not in json.dumps(failure)


def test_persistent_clock_blocks_replaced_audit_db_and_stays_failed(tmp_path):
    """A valid-looking replacement DB cannot fool a running time high-water mark."""
    from shards_kernel.common.time import ClockRollbackError, PersistentSystemClock

    database, _ = _audit(tmp_path)
    clock = PersistentSystemClock(
        str(database), "restore-example", source_ns=lambda: 2_000_000_000
    )
    assert clock.now_ms() == 2_000
    prior = tmp_path / "prior.sqlite3"
    database.rename(prior)
    SQLiteAuditStorage(str(database)).bind_kernel("restore-example", "strict")
    with pytest.raises(ClockRollbackError):
        clock.now_ms()
    with pytest.raises(ClockRollbackError, match="declared unsafe"):
        clock.now_ms()


def test_persistent_clock_rejects_symlinked_database_replacement(tmp_path):
    """Symlink restoration cannot silently substitute for the enrolled inode."""
    from shards_kernel.common.time import ClockRollbackError, PersistentSystemClock

    database, _ = _audit(tmp_path)
    clock = PersistentSystemClock(
        str(database), "restore-example", source_ns=lambda: 2_000_000_000
    )
    assert clock.now_ms() == 2_000
    relocated = tmp_path / "relocated.sqlite3"
    database.rename(relocated)
    database.symlink_to(relocated)
    with pytest.raises(ClockRollbackError):
        clock.now_ms()
