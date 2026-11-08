"""Published v0.1.3 package acceptance: no repository source imports.

This is executed only from an isolated directory with an installed wheel.
The checks intentionally do not claim multi-host or production readiness.
"""

from concurrent.futures import ThreadPoolExecutor
from importlib import metadata
from pathlib import Path
from threading import Barrier
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from implementations.storage import SQLiteAuditStorage
from shards_kernel.common.errors import AuditError
from shards_kernel.common.types import KernelConfig, KernelRequest, ToolCall, VirtualClock
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel


VERSION = "0.1.3"


def boot(db, kernel_id="published-acceptance", clock_ms=1000):
    kernel = StrictKernel(audit_storage=SQLiteAuditStorage(str(db)))
    kernel.boot(KernelConfig(
        kernel_id=kernel_id, variant="strict", clock=VirtualClock(clock_ms)
    ))
    return kernel


def test_published_distribution_is_not_source_checkout():
    import shards_kernel

    assert metadata.version("shards-kernel") == VERSION
    location = Path(shards_kernel.__file__).resolve()
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        assert not location.is_relative_to(Path(workspace).resolve()), location
    assert "site-packages" in location.parts or "dist-packages" in location.parts


def test_offline_cli_demo_all_seven_invariants():
    run = subprocess.run(
        [sys.executable, "-m", "shards_kernel", "demo", "--json"],
        capture_output=True, text=True, check=True, timeout=30,
    )
    result = json.loads(run.stdout)
    expected = {
        "missing_permit", "approved_execution", "same_permit_replay",
        "scope_change", "expired_permit", "revoked_signing_key",
        "ledger_recovered_replay",
    }
    checks = result["checks"]
    assert len(checks) == len(expected)
    assert {item["id"] for item in checks} == expected
    assert all(item["passed"] is True for item in checks)
    assert result["passed"] is True
    assert result["private_key_exposed"] is False
    assert result["production_ready"] is False


def test_sqlite_recovery_and_modified_entry_refusal(tmp_path):
    db = tmp_path / "tamper.sqlite3"
    kernel = boot(db)
    kernel.submit(KernelRequest(
        request_id="original", ts_ms=1000, actor="tester",
        intent="original event",
    ))
    original = kernel.export_evidence()
    assert len(original.ledger_entries) == 1
    recovered = boot(db).export_evidence()
    assert recovered.root_hash == original.root_hash
    assert recovered.ledger_entries == original.ledger_entries

    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT rowid, payload_json FROM audit_entries LIMIT 1"
        ).fetchone()
        assert row is not None
        payload = json.loads(row[1])
        payload["intent"] = "tampered"
        conn.execute(
            "UPDATE audit_entries SET payload_json=? WHERE rowid=?",
            (json.dumps(payload), row[0]),
        )
    with pytest.raises(AuditError, match="hash chain verification failed"):
        boot(db)


def test_truncation_requires_independently_retained_root(tmp_path):
    db = tmp_path / "rollback.sqlite3"
    kernel = boot(db, kernel_id="rollback-check")
    for n in range(2):
        kernel.submit(KernelRequest(
            request_id=f"event-{n}", ts_ms=1000,
            actor="tester", intent=f"event {n}",
        ))
    original = kernel.export_evidence()
    assert len(original.ledger_entries) == 2
    trusted_root = original.root_hash  # Test-only simulation; NOT off-host custody.
    with sqlite3.connect(db) as conn:
        deleted = conn.execute(
            "DELETE FROM audit_entries WHERE ledger_seq = "
            "(SELECT MAX(ledger_seq) FROM audit_entries)"
        )
        assert deleted.rowcount == 1
    recovered = boot(db, kernel_id="rollback-check").export_evidence()
    assert len(recovered.ledger_entries) == 1
    # Explicitly document the local hash chain's known truncation limitation.
    assert recovered.root_hash != trusted_root


def test_single_instance_20_thread_single_use_budget():
    keyring = {"acceptance": os.urandom(32)}  # Test-only HMAC fixture.
    for round_no in range(5):
        kernel = StrictKernel()
        kernel.boot(KernelConfig(
            kernel_id=f"threads-{round_no}", variant="strict",
            clock=VirtualClock(1000),
        ))
        kernel.set_keyring(keyring)
        params = {"text": "approved"}
        permit = (
            PermitBuilder().issuer("operator").subject("agent")
            .jurisdiction("default").action("echo")
            .params(params).constraints({}).max_executions(1)
            .valid_from_ms(0).valid_until_ms(2000)
            .evidence_hash("fixture").proposal_hash("fixture")
            .build(keyring, "acceptance")
        )
        start = Barrier(20)

        def submit(index):
            request = KernelRequest(
                request_id=f"request-{round_no}-{index}", ts_ms=1000,
                actor="agent", intent="test concurrent admission",
                tool_call=ToolCall(name="echo", params=dict(params)),
                params=dict(params),
            )
            start.wait(timeout=20)
            receipt = kernel.submit(request, permit_token=permit)
            return receipt.decision.value, receipt.tool_result

        with ThreadPoolExecutor(max_workers=20) as pool:
            receipts = list(pool.map(submit, range(20)))
        assert sum(decision == "ALLOW" for decision, _ in receipts) == 1
        assert sum(result == "approved" for _, result in receipts) == 1
