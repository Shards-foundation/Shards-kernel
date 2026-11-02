"""Single-host persistent UTC time checkpoint across kernel process restarts."""

import sqlite3
from pathlib import Path

import pytest

from shards_kernel.common.time import ClockRollbackError, PersistentSystemClock
from shards_kernel.cli.service import build_operator_server, parse_operator_config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _database(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE init_probe (x INTEGER)")
    return path


def test_persistent_time_rejects_rollback_across_independent_clock_instances(tmp_path):
    path = _database(tmp_path)
    first = PersistentSystemClock(str(path), "kernel-a", source_ns=lambda: 2_000_000_000)
    assert first.now_ms() == 2000
    assert first.now_ms() == 2000
    bad = PersistentSystemClock(str(path), "kernel-a", source_ns=lambda: 1_999_000_000)
    with pytest.raises(ClockRollbackError, match="cannot validate"):
        bad.now_ms()
    with pytest.raises(ClockRollbackError, match="declared unsafe"):
        bad.now_ms()

    resumed = PersistentSystemClock(str(path), "kernel-a", source_ns=lambda: 2_100_000_000)
    assert resumed.now_ms() == 2100
    with sqlite3.connect(path) as conn:
        stored = conn.execute(
            "SELECT last_ms FROM kernel_clock_checkpoint WHERE kernel_id='kernel-a'"
        ).fetchone()
    assert stored == (2100,)


def test_local_clock_state_is_scoped_to_kernel_identity(tmp_path):
    path = _database(tmp_path)
    first = PersistentSystemClock(str(path), "first", source_ns=lambda: 10_000_000_000)
    assert first.now_ms() == 10_000
    second = PersistentSystemClock(str(path), "second", source_ns=lambda: 9_000_000_000)
    assert second.now_ms() == 9000
    assert first.now_ms() == 10_000


def test_cannot_replace_erase_or_symlink_clock_database(tmp_path):
    path = _database(tmp_path)
    clock = PersistentSystemClock(str(path), "main", source_ns=lambda: 123_000_000)
    assert clock.now_ms() == 123
    old = tmp_path / "old.sqlite3"
    path.rename(old)
    _database(tmp_path)  # creates evidence.sqlite3 with another inode
    with pytest.raises(ClockRollbackError):
        clock.now_ms()
    with pytest.raises(ClockRollbackError, match="declared unsafe"):
        clock.now_ms()

    symlink = tmp_path / "symlink.sqlite3"
    symlink.symlink_to(path)
    with pytest.raises(ClockRollbackError):
        PersistentSystemClock(str(symlink), "main")


def test_malformed_or_erased_watermark_fails_closed(tmp_path):
    path = _database(tmp_path)
    clock = PersistentSystemClock(str(path), "kernel-a", source_ns=lambda: 1_000_000_000)
    assert clock.now_ms() == 1000
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE kernel_clock_checkpoint SET last_ms=? WHERE kernel_id=?",
            ("bad-text", "kernel-a"),
        )
    new = PersistentSystemClock(str(path), "kernel-a", source_ns=lambda: 2_000_000_000)
    with pytest.raises(ClockRollbackError):
        new.now_ms()


def test_operator_service_uses_persistent_clock(tmp_path):
    signer = Ed25519PrivateKey.generate()
    data = {
        "version": 1,
        "kernel_id": "clocked-operator",
        "actor": "operator-agent",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "operator",
            "issuer": "issuer",
            "public_key_hex": signer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": 8765,
    }
    config = parse_operator_config(data)
    import secrets
    secret = secrets.token_urlsafe(36)
    server = build_operator_server(config, api_key=secret)
    assert isinstance(server.kernel.config.clock, PersistentSystemClock)
    before = server.kernel.config.clock.now_ms()
    assert before > 0
    another = build_operator_server(config, api_key=secret)
    assert another.kernel.config.clock.now_ms() >= before
