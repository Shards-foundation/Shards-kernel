"""Read-only SQLite audit snapshot and isolated restore rehearsal.

This *does not* create a durable backup, sign evidence, restore production,
verify external side effects, or authorise a production release.

Snapshot uses sqlite3.Connection.backup() so committed WAL transactions are
included. All boot/ledger replay occurs on a disposable private copy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from implementations.storage import SQLiteAuditStorage
from shards_kernel.audit.ledger import AuditLedger


class DrillError(Exception):
    """A bounded public error code, never a DB path or secret."""


@dataclass(frozen=True)
class DrillResult:
    kernel_id: str
    entry_count: int
    root_hash: str
    pending_intents: int
    policy_revision: int | None
    external_root_compared: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "LOCAL_RESTORE_VERIFIED",
            "kernel_id": self.kernel_id,
            "entry_count": self.entry_count,
            "root_hash": self.root_hash,
            "pending_intents": self.pending_intents,
            "policy_revision": self.policy_revision,
            "external_root_compared": self.external_root_compared,
            "scope": "single-host disposable SQLite replay only",
        }


def _readonly_uri(path: Path) -> str:
    return "file:" + quote(str(path), safe="/") + "?mode=ro"


def _source_identity(path: Path) -> tuple[int, int]:
    if not path.is_absolute():
        raise DrillError("ABSOLUTE_SOURCE_PATH_REQUIRED")
    try:
        info = path.lstat()
    except OSError as exc:
        raise DrillError("SOURCE_UNAVAILABLE") from exc
    if not stat.S_ISREG(info.st_mode):
        raise DrillError("SOURCE_MUST_BE_REGULAR_FILE")
    return info.st_dev, info.st_ino


def _open_private_source(path: Path, expected: tuple[int, int]) -> int:
    """Pin a no-follow FD inside a directory not writable by other users.

    sqlite3's standard Python API opens by pathname rather than by an
    already-open FD. That is safe against *other OS users* only if the parent
    directory is private to this operator UID. A hostile process running
    under the operator UID is not isolated by this check and remains out of
    scope for this single-host diagnostic.
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise DrillError("SECURE_LOCAL_FILESYSTEM_REQUIRED")
    directory = path.parent
    try:
        directory_info = directory.stat()
        if (
            directory.is_symlink()
            or directory.resolve() != directory
            or directory_info.st_uid != os.geteuid()
            or directory_info.st_mode & 0o077
        ):
            raise DrillError("PRIVATE_SOURCE_DIRECTORY_REQUIRED")
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except DrillError:
        raise
    except OSError as exc:
        raise DrillError("SOURCE_UNAVAILABLE_OR_REPLACED") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != expected
            or (info.st_mode & 0o077)
            or info.st_uid != os.geteuid()
            or _source_identity(path) != expected
        ):
            raise DrillError("UNSAFE_OR_CHANGED_SOURCE")
        return fd
    except Exception:
        os.close(fd)
        raise


def _integrity_check(connection: sqlite3.Connection) -> None:
    # Never permit a SQLite filesystem that is corrupt to count as recovered.
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if integrity != [("ok",)]:
        raise DrillError("SQLITE_INTEGRITY_FAILURE")


def _policy_revision(connection: sqlite3.Connection, kernel_id: str) -> int | None:
    present = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='operator_policy_checkpoint'"
    ).fetchone()
    if not present:
        return None
    row = connection.execute(
        "SELECT revision FROM operator_policy_checkpoint WHERE kernel_id=?",
        (kernel_id,),
    ).fetchone()
    if row is None:
        return None
    value = row[0]
    if type(value) is not int or value < 1:
        raise DrillError("INVALID_POLICY_CHECKPOINT")
    return value


def _unreconciled_intents(entries: tuple[object, ...]) -> int:
    """Only an immediately adjacent, correlated successful execution closes intent.

    Denials and failures may use audit_phase="outcome" without executing a tool.
    A later retry with the same request ID must never erase an earlier
    side-effect ambiguity. False negatives (requiring manual review) are safer
    than silently treating a failed attempt as a completed execution.
    """
    from shards_kernel.common.types import Decision

    identity_fields = (
        "request_id", "actor", "tool_name", "params_hash",
        "permit_digest", "permit_nonce", "permit_issuer", "permit_subject",
    )
    pending = 0
    for index, intent in enumerate(entries):
        if intent.audit_phase != "intent":
            continue
        if index + 1 >= len(entries):
            pending += 1
            continue
        outcome = entries[index + 1]
        if (
            intent.permit_digest is None
            or intent.permit_nonce is None
            or intent.permit_verification != "INTENT"
            or outcome.audit_phase != "outcome"
            or outcome.decision != Decision.ALLOW
            or outcome.permit_verification != "OUTCOME"
            or outcome.error is not None
            or any(getattr(intent, key) != getattr(outcome, key) for key in identity_fields)
        ):
            pending += 1
    return pending


def verify_restore(
    *,
    source: Path,
    kernel_id: str,
    expected_root: str | None = None,
    min_entries: int = 1,
    min_policy_revision: int | None = None,
) -> DrillResult:
    """Verify a disposable restored SQLite snapshot without writing the source."""
    if not isinstance(kernel_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", kernel_id):
        raise DrillError("INVALID_KERNEL_ID")
    if expected_root is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_root):
        raise DrillError("INVALID_EXPECTED_ROOT")
    if type(min_entries) is not int or min_entries < 1:
        raise DrillError("INVALID_MIN_ENTRIES")
    if min_policy_revision is not None and (
        type(min_policy_revision) is not int or min_policy_revision < 1
    ):
        raise DrillError("INVALID_MIN_POLICY_REVISION")

    identity = _source_identity(source)
    try:
        # Keep a no-follow FD open for the entire read; require a private 0700
        # source directory so other UIDs cannot swap the SQLite pathname while
        # sqlite3 opens it. A same-UID hostile process remains outside scope.
        source_fd = _open_private_source(source, identity)
        try:
            # A private temporary copy is intentionally erased on success/error.
            with tempfile.TemporaryDirectory(prefix="shards-restore-drill-") as folder:
                snapshot = Path(folder) / "restored.sqlite3"
                fd = os.open(str(snapshot), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(fd)
                with closing(sqlite3.connect(_readonly_uri(source), uri=True, timeout=5)) as src:
                    if _source_identity(source) != identity:
                        raise DrillError("SOURCE_CHANGED_DURING_SNAPSHOT")
                    with closing(sqlite3.connect(str(snapshot), timeout=5)) as dst:
                        src.backup(dst, pages=64, sleep=0.05)

                if _source_identity(source) != identity:
                    raise DrillError("SOURCE_CHANGED_DURING_SNAPSHOT")

                with closing(sqlite3.connect(_readonly_uri(snapshot), uri=True)) as restored:
                    restored.execute("PRAGMA query_only=ON")
                    _integrity_check(restored)
                    row = restored.execute(
                        "SELECT variant FROM audit_kernel_metadata WHERE kernel_id=?",
                        (kernel_id,),
                    ).fetchone()
                    if row is None or row[0] not in (
                        "strict", "permissive", "evidence-first", "dual-channel"
                    ):
                        raise DrillError("KERNEL_METADATA_MISSING")
                    variant = row[0]
                    checkpoint = _policy_revision(restored, kernel_id)

                if min_policy_revision is not None and (
                    checkpoint is None or checkpoint < min_policy_revision
                ):
                    raise DrillError("POLICY_REVISION_BELOW_TRUSTED_FLOOR")

                # Exercise the real ledger restoration and hash-chain verifier on
                # the copied DB. No operator/server/network/tool execution occurs.
                ledger = AuditLedger(
                    kernel_id, variant, storage=SQLiteAuditStorage(str(snapshot))
                )
                if ledger.length < min_entries:
                    raise DrillError("MINIMUM_AUDIT_ENTRIES_NOT_MET")
                pending = _unreconciled_intents(ledger.entries)
                if pending:
                    raise DrillError("UNRECONCILED_EXECUTION_INTENTS")
                if expected_root is not None and ledger.root_hash != expected_root:
                    raise DrillError("EXTERNAL_ROOT_MISMATCH")
                return DrillResult(
                    kernel_id=kernel_id,
                    entry_count=ledger.length,
                    root_hash=ledger.root_hash,
                    pending_intents=pending,
                    policy_revision=checkpoint,
                    external_root_compared=expected_root is not None,
                )
        finally:
            os.close(source_fd)
    except DrillError:
        raise
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        raise DrillError("SNAPSHOT_OR_REPLAY_REJECTED") from exc
    except Exception as exc:
        # A corrupt ledger may raise a kernel-specific AuditError. Do not
        # print the exception: audit row data may contain sensitive context.
        raise DrillError("SNAPSHOT_OR_REPLAY_REJECTED") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OFFLINE disposable audit restore drill; NOT a backup service"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--kernel-id", required=True)
    parser.add_argument("--expected-root", default=None)
    parser.add_argument("--min-entries", type=int, default=1)
    parser.add_argument("--min-policy-revision", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        report = verify_restore(
            source=args.source,
            kernel_id=args.kernel_id,
            expected_root=args.expected_root,
            min_entries=args.min_entries,
            min_policy_revision=args.min_policy_revision,
        )
    except DrillError as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}))
        return 2
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
