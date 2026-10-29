#!/usr/bin/env python3
"""Example 03: archive and re-verify exported evidence using SQLite.

This example archives evidence after the kernel request has completed. It
demonstrates the storage helper; it does NOT claim that SQLite persistence is
wired into the kernel's pre-execution audit boundary.
"""

import tempfile
from pathlib import Path

from implementations.storage import SQLiteAuditStorage
from kernels.audit.replay import replay_and_verify
from kernels.common.codec import audit_entry_to_dict
from kernels.common.types import KernelConfig, KernelRequest, VirtualClock
from kernels.variants.strict_kernel import StrictKernel


def main() -> None:
    """Create evidence, persist it, reopen the database, and verify it."""
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id="demo-sqlite-003",
            variant="strict",
            clock=VirtualClock(3_000),
        )
    )
    kernel.submit(
        KernelRequest(
            request_id="demo-request-003",
            ts_ms=3_000,
            actor="demo-operator",
            intent="Demonstrate evidence archiving",
        )
    )
    evidence = kernel.export_evidence()
    entries = [audit_entry_to_dict(entry) for entry in evidence.ledger_entries]

    with tempfile.TemporaryDirectory(prefix="kernels-demo-") as temp_dir:
        database = Path(temp_dir) / "evidence.sqlite3"
        storage = SQLiteAuditStorage(str(database))
        for entry in entries:
            storage.append(evidence.kernel_id, entry)

        # Reopen via a new storage instance to prove the rows outlive the
        # original connection and can be read back from the database file.
        reopened = SQLiteAuditStorage(str(database))
        archived = reopened.list_entries(evidence.kernel_id)
        valid, errors = replay_and_verify(
            archived,
            expected_root_hash=evidence.root_hash,
        )

        print(f"Database: {database.name}")
        print(f"Archived entries: {len(archived)}")
        print(f"Storage health: {'PASS' if reopened.health()['ok'] else 'FAIL'}")
        print(f"Archived hash-chain verification: {'PASS' if valid else 'FAIL'}")
        if errors:
            for error in errors:
                print(f"  - {error}")
        if len(archived) != len(entries) or not valid:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
