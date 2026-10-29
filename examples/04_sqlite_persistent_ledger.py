#!/usr/bin/env python3
"""Example 03: run a kernel with a durable SQLite audit ledger.

Unlike the archive-only example, this demo injects SQLite storage into the
kernel. Each audit append is committed before the in-memory ledger advances.
The kernel restores and verifies the hash chain when restarted with the same
database, kernel ID, and variant.
"""

import tempfile
from pathlib import Path

from implementations.storage import SQLiteAuditStorage
from kernels.common.types import KernelConfig, KernelRequest, VirtualClock
from kernels.variants.strict_kernel import StrictKernel


def config(clock_ms: int) -> KernelConfig:
    """Return a reproducible strict-kernel configuration."""
    return KernelConfig(
        kernel_id="demo-sqlite-003",
        variant="strict",
        clock=VirtualClock(clock_ms),
    )


def main() -> None:
    """Persist an audit ledger, restart, and verify recovery."""
    with tempfile.TemporaryDirectory(prefix="kernels-demo-") as temp_dir:
        database = Path(temp_dir) / "audit.sqlite3"
        storage = SQLiteAuditStorage(str(database))

        kernel = StrictKernel(audit_storage=storage)
        kernel.boot(config(3_000))
        kernel.submit(
            KernelRequest(
                request_id="demo-request-003",
                ts_ms=3_000,
                actor="demo-operator",
                intent="Demonstrate durable audit-before-completion",
            )
        )
        original = kernel.export_evidence()

        # Reopening the database and constructing a new kernel verifies and
        # restores the stored ledger before the new kernel can accept requests.
        restarted = StrictKernel(
            audit_storage=SQLiteAuditStorage(str(database))
        )
        restarted.boot(config(4_000))
        recovered = restarted.export_evidence()
        health = SQLiteAuditStorage(str(database)).health()

        print(f"Database: {database.name}")
        print(f"Persisted entries: {len(original.ledger_entries)}")
        print(f"Recovered entries: {len(recovered.ledger_entries)}")
        print(f"Root hash recovered: {recovered.root_hash == original.root_hash}")
        print(f"Storage health: {'PASS' if health['ok'] else 'FAIL'}")

        if (
            not health["ok"]
            or recovered.root_hash != original.root_hash
            or recovered.ledger_entries != original.ledger_entries
        ):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
