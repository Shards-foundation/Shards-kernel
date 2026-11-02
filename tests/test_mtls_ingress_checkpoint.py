"""Signed v2 mTLS policy: local revision anti-rollback, restart and live denial."""

from __future__ import annotations

import copy
import os
import sqlite3
import time

import pytest

from shards_kernel.integrations.mtls_checkpoint import (
    bootstrap_ingress_checkpoint, checkpoint_ingress_revision, verify_ingress_checkpoint,
)
from shards_kernel.integrations.mtls_ingress import (
    MTLSIngressServer, verify_ingress_policy,
)
from shards_kernel.issuer import sign_mtls_ingress_policy
from tests.test_mtls_agent_ingress import _body, _https, _setup


def _versioned(tmp_path, *, revision=1, ingress_id="primary-ingress"):
    env = _setup(tmp_path)
    checkpoint_path = tmp_path / "ingress-checkpoint.sqlite3"
    with sqlite3.connect(checkpoint_path):
        pass
    os.chmod(checkpoint_path, 0o600)
    raw = copy.deepcopy(env["policy"]["config"])
    raw["ingress_id"] = ingress_id
    raw["checkpoint_db_file"] = str(checkpoint_path)
    now = int(time.time() * 1000)
    policy = sign_mtls_ingress_policy(
        raw, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=revision,
    )
    config = verify_ingress_policy(
        policy, pinned_public_key_hex=env["pinned"], now_ms=now,
    )
    bootstrap_ingress_checkpoint(
        checkpoint_path, ingress_id=config.ingress_id,
        revision=config.revision, digest=config.policy_digest,
    )
    return env, raw, policy, config, checkpoint_path


def test_v2_signature_explicit_revision_and_signed_checkpoint_path(tmp_path):
    env, raw, policy, config, path = _versioned(tmp_path)
    assert config.revision == 1
    assert config.ingress_id == "primary-ingress"
    assert config.checkpoint_db_file == path
    assert config.policy_digest and len(config.policy_digest) == 64
    assert policy["schema"] == "shards.mtls-ingress.v2"
    assert policy["revision"] == 1
    for change in (
        {"revision": 2}, {"revision": 0}, {"revision": True},
        {"revision": "2"}, {"revision": -1}, {"checkpoint": "forged"},
    ):
        forged = dict(policy, **change)
        with pytest.raises(ValueError):
            verify_ingress_policy(
                forged, pinned_public_key_hex=env["pinned"],
                now_ms=int(time.time() * 1000),
            )
    modified = copy.deepcopy(policy)
    modified["config"]["checkpoint_db_file"] = str(tmp_path / "other.sqlite3")
    with pytest.raises(ValueError, match="signature"):
        verify_ingress_policy(
            modified, pinned_public_key_hex=env["pinned"],
            now_ms=int(time.time() * 1000),
        )
    with pytest.raises(ValueError, match="revision"):
        sign_mtls_ingress_policy(
            raw, env["ingress_key"], issued_at_ms=1,
            expires_at_ms=10, revision=-1,
        )


def test_signed_revision_checkpoint_survives_restart_and_denies_rollback(tmp_path):
    env, raw, original, v1, path = _versioned(tmp_path)
    server = MTLSIngressServer(v1)
    server._verify_policy_checkpoint()
    server = MTLSIngressServer(v1)  # Same signed revision restart is idempotent.
    server._verify_policy_checkpoint()
    now = int(time.time() * 1000)
    newer = sign_mtls_ingress_policy(
        raw, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=2,
    )
    v2 = verify_ingress_policy(
        newer, pinned_public_key_hex=env["pinned"], now_ms=now,
    )
    upgraded = MTLSIngressServer(v2)
    # Merely constructing the v2 ingress does NOT ratchet persistent trust.
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
            (v1.ingress_id,),
        ).fetchone() == (1,)
    upgraded.start(blocking=False)
    try:
        upgraded._verify_policy_checkpoint()
    finally:
        upgraded.stop()
    with pytest.raises(ValueError, match="rollback"):
        MTLSIngressServer(v1)
    with pytest.raises(ValueError, match="no longer matches"):
        server._verify_policy_checkpoint()
    assert path.is_file() and original["revision"] == 1


def test_same_revision_different_signed_policy_denied(tmp_path):
    env, raw, _, config, _ = _versioned(tmp_path)
    MTLSIngressServer(config)
    changed = copy.deepcopy(raw)
    changed["listen_port"] = env["ingress_port"] + 1
    now = int(time.time() * 1000)
    signed = sign_mtls_ingress_policy(
        changed, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=1,
    )
    alternative = verify_ingress_policy(
        signed, pinned_public_key_hex=env["pinned"], now_ms=now,
    )
    with pytest.raises(ValueError, match="digest substitution"):
        MTLSIngressServer(alternative)


def test_runtime_database_replacement_corruption_and_permissions_fail_closed(tmp_path):
    _, _, _, config, path = _versioned(tmp_path)
    server = MTLSIngressServer(config)
    server._verify_policy_checkpoint()
    original = path.with_suffix(".previous")
    path.rename(original)  # Preserve old inode so reuse cannot hide replacement.
    with sqlite3.connect(path):
        pass
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="replaced"):
        server._verify_policy_checkpoint()
    with pytest.raises(ValueError, match="replaced"):
        # Empty replacement can *not* be mistaken for the previous database
        # by the already running server; new process would require a
        # separate external trusted anchor, still an explicit P0 gap.
        verify_ingress_checkpoint(
            path, ingress_id=config.ingress_id, revision=1,
            digest="0" * 64, identity=server._checkpoint_identity,
        )


def test_private_checkpoint_required_before_socket_binding(tmp_path):
    env, raw, _, config, path = _versioned(tmp_path)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        MTLSIngressServer(config)
    path.chmod(0o600)
    renamed = tmp_path / "ingress-moved.db"
    path.rename(renamed)
    path.symlink_to(renamed)
    with pytest.raises(ValueError, match="regular"):
        MTLSIngressServer(config)
    with pytest.raises(ValueError, match="revision"):
        sign_mtls_ingress_policy(raw, env["ingress_key"], issued_at_ms=1,
                                 expires_at_ms=10, revision=True)


def test_runtime_rejects_newer_checkpoint_without_forward(tmp_path):
    env, raw, _, config, path = _versioned(tmp_path)
    ingress = MTLSIngressServer(config)
    ingress.start(blocking=False)
    try:
        port, ca, alpha = env["ingress_port"], env["files"]["ca"], env["files"]["alpha"]
        body = _body("agent-alpha", "before-upgrade", "echo", {"text": "x"})
        assert _https(port, ca, alpha, bearer=env["alpha"], payload=body)[0] == 502
        checkpoint_ingress_revision(
            path, ingress_id=config.ingress_id, revision=2,
            digest="a" * 64,
        )
        body = _body("agent-alpha", "after-upgrade", "echo", {"text": "x"})
        status, receipt = _https(
            port, ca, alpha, bearer=env["alpha"], payload=body,
        )
        assert status == 503
        assert receipt["error"] == "Ingress policy checkpoint or clock unavailable"
    finally:
        ingress.stop()


def test_checkpoint_corrupted_or_deleted_state_is_not_an_authority(tmp_path):
    _, _, _, config, path = _versioned(tmp_path)
    server = MTLSIngressServer(config)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM ingress_policy_checkpoint")
    with pytest.raises(ValueError, match="no longer matches"):
        server._verify_policy_checkpoint()
    with pytest.raises(ValueError, match="Missing enrolled"):
        MTLSIngressServer(config)  # Must not re-enrol deleted rows.
    with pytest.raises(ValueError, match="already initialised"):
        bootstrap_ingress_checkpoint(
            path, ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
        )
    # Local checkpoints are not an external tamper-evident anchor;
    # externally backed proof is an intentionally separate release gate.
    path.write_bytes(b"bad database")
    with pytest.raises(ValueError, match="unavailable"):
        MTLSIngressServer(config)


@pytest.mark.parametrize("missing", [
    "checkpoint_db_file", "ingress_id", "policy_digest", "_checkpoint_identity",
])
def test_missing_runtime_checkpoint_authority_is_rejected(missing):
    """Each missing trust field fails closed without relying on Python asserts."""
    from pathlib import Path
    from types import SimpleNamespace

    ingress = object.__new__(MTLSIngressServer)
    ingress.config = SimpleNamespace(
        revision=1, checkpoint_db_file=Path("/nonexistent/checkpoint.sqlite3"),
        ingress_id="test-ingress", policy_digest="a" * 64,
    )
    ingress._checkpoint_identity = (10, 20)
    if missing == "_checkpoint_identity":
        ingress._checkpoint_identity = None
    else:
        setattr(ingress.config, missing, None)
    with pytest.raises(ValueError, match="Missing signed ingress checkpoint authority"):
        ingress._verify_policy_checkpoint()


def test_empty_existing_checkpoint_never_auto_enrols(tmp_path):
    """An attacker cannot erase the local checkpoint and restart at revision one."""
    _, _, _, config, db = _versioned(tmp_path)
    initial = MTLSIngressServer(config)
    initial._verify_policy_checkpoint()
    db.unlink()
    with sqlite3.connect(db):
        pass
    os.chmod(db, 0o600)
    with pytest.raises(ValueError, match="unavailable"):
        MTLSIngressServer(config)
    # A new blank file is not a trusted recovery path without an explicit
    # operator bootstrap. This is not protection from whole-DB rollback.
    bootstrap_ingress_checkpoint(
        db, ingress_id=config.ingress_id,
        revision=config.revision, digest=config.policy_digest,
    )
    MTLSIngressServer(config)._verify_policy_checkpoint()


def test_checkpoint_bootstrap_requires_virgin_database_and_is_one_shot(tmp_path):
    _, _, _, config, db = _versioned(tmp_path)
    with pytest.raises(ValueError, match="already initialised"):
        bootstrap_ingress_checkpoint(
            db, ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
        )
    with pytest.raises(ValueError, match="existing absolute regular file"):
        checkpoint_ingress_revision(
            tmp_path / "does-not-exist.sqlite3",
            ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
        )


def test_runtime_rejects_removed_schema_without_recreating_it(tmp_path):
    _, _, _, config, db = _versioned(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE ingress_policy_checkpoint")
    with pytest.raises(ValueError, match="unavailable"):
        MTLSIngressServer(config)


def test_fresh_private_db_refuses_ingress_until_explicit_bootstrap(tmp_path):
    """Creating an empty file must never itself grant signed ingress authority."""
    _, _, _, signed_config, db = _versioned(tmp_path)
    db.unlink()
    db.touch(mode=0o600)
    with pytest.raises(ValueError, match="unavailable"):
        MTLSIngressServer(signed_config)
    # Deliberate one-time operator action establishes the initial high-water
    # mark; subsequent normal restarts may verify, not initialise, the DB.
    identity = bootstrap_ingress_checkpoint(
        db, ingress_id=signed_config.ingress_id,
        revision=signed_config.revision, digest=signed_config.policy_digest,
    )
    assert identity == MTLSIngressServer(signed_config)._checkpoint_identity
    with pytest.raises(ValueError, match="already initialised"):
        bootstrap_ingress_checkpoint(
            db, ingress_id=signed_config.ingress_id,
            revision=signed_config.revision, digest=signed_config.policy_digest,
        )


def test_checkpoint_connections_explicitly_close_on_success_and_failure(
    tmp_path, monkeypatch,
):
    """No SQLite descriptors may leak across TLS request policy checks.

    Hold every created connection alive to prevent Python's refcounting or GC
    from disguising an omitted close(). This proves explicit close on all
    three checkpoint operations, including exceptions inside transactions.
    """
    from shards_kernel.integrations import mtls_checkpoint as checkpoint_module

    _, _, _, config, path = _versioned(tmp_path)
    created = []
    connect = sqlite3.connect

    class TrackedConnection(sqlite3.Connection):
        closed_explicitly = False

        def close(self):
            self.closed_explicitly = True
            return super().close()

    def track_connect(*args, **kwargs):
        connection = connect(*args, factory=TrackedConnection, **kwargs)
        created.append(connection)
        return connection

    monkeypatch.setattr(checkpoint_module.sqlite3, "connect", track_connect)
    server = MTLSIngressServer(config)

    for _ in range(125):
        server._verify_policy_checkpoint()

    # A bootstrap attempt against enrolled state must rollback and close.
    with pytest.raises(ValueError, match="already initialised"):
        bootstrap_ingress_checkpoint(
            path, ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
        )

    # Revision rollback and signed digest substitution must also close.
    checkpoint_ingress_revision(
        path, ingress_id=config.ingress_id,
        revision=2, digest="a" * 64,
    )
    with pytest.raises(ValueError, match="rollback"):
        checkpoint_ingress_revision(
            path, ingress_id=config.ingress_id,
            revision=1, digest=config.policy_digest,
        )
    with pytest.raises(ValueError, match="no longer matches"):
        server._verify_policy_checkpoint()

    # Retain live Python references to every connection; garbage collection
    # cannot act as a substitute for explicit release of SQLite resources.
    assert len(created) >= 130
    assert all(connection.closed_explicitly for connection in created)


def test_checkpoint_replacement_within_transactions_fails_and_rolls_back(
    tmp_path, monkeypatch,
):
    """A replacement detected before commit must not advance signed trust."""
    from shards_kernel.integrations import mtls_checkpoint as module

    _, _, _, config, path = _versioned(tmp_path)
    real_identity = module._identity
    original = real_identity(path)
    counter = [0]

    def replaced_after_admission(source):
        counter[0] += 1
        return original if counter[0] == 1 else (original[0], original[1] + 1)

    monkeypatch.setattr(module, "_identity", replaced_after_admission)
    with pytest.raises(ValueError, match="changed during update"):
        checkpoint_ingress_revision(
            path, ingress_id=config.ingress_id, revision=2,
            digest="b" * 64,
        )
    # The failed transaction must have been rolled back, not merely denied.
    monkeypatch.setattr(module, "_identity", real_identity)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
            (config.ingress_id,),
        ).fetchone() == (1,)

    counter[0] = 0
    monkeypatch.setattr(module, "_identity", replaced_after_admission)
    with pytest.raises(ValueError, match="replaced"):
        verify_ingress_checkpoint(
            path, ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
            identity=original,
        )

    virgin = tmp_path / "bootstrap-virgin.sqlite3"
    with sqlite3.connect(virgin):
        pass
    virgin.chmod(0o600)
    original = real_identity(virgin)
    counter[0] = 0
    with pytest.raises(ValueError, match="changed during bootstrap"):
        bootstrap_ingress_checkpoint(
            virgin, ingress_id=config.ingress_id,
            revision=config.revision, digest=config.policy_digest,
        )
    monkeypatch.setattr(module, "_identity", real_identity)
    with sqlite3.connect(virgin) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name='ingress_policy_checkpoint'"
        ).fetchone() is None


def test_checkpoint_invalid_identity_wrong_owner_and_malformed_sqlite(
    tmp_path, monkeypatch,
):
    """Reject malformed pinned authority even when the path is a regular file."""
    from shards_kernel.integrations import mtls_checkpoint as module

    _, _, _, config, path = _versioned(tmp_path)
    with pytest.raises(ValueError, match="Invalid signed ingress revision identity"):
        checkpoint_ingress_revision(
            path, ingress_id=config.ingress_id, revision=True,
            digest=config.policy_digest,
        )
    with pytest.raises(ValueError, match="Invalid signed ingress revision identity"):
        checkpoint_ingress_revision(
            path, ingress_id="not a valid actor", revision=1,
            digest=config.policy_digest,
        )

    if hasattr(os, "getuid"):
        monkeypatch.setattr(module.os, "getuid", lambda: os.stat(path).st_uid + 1)
        with pytest.raises(ValueError, match="serving user"):
            checkpoint_ingress_revision(
                path, ingress_id=config.ingress_id, revision=1,
                digest=config.policy_digest,
            )
        monkeypatch.undo()

    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"invalid sqlite database bytes")
    malformed.chmod(0o600)
    with pytest.raises(ValueError, match="unavailable"):
        bootstrap_ingress_checkpoint(
            malformed, ingress_id=config.ingress_id,
            revision=1, digest="a" * 64,
        )
    with pytest.raises(ValueError, match="unavailable"):
        checkpoint_ingress_revision(
            malformed, ingress_id=config.ingress_id,
            revision=1, digest="a" * 64,
        )
    with pytest.raises(ValueError, match="unavailable"):
        verify_ingress_checkpoint(
            malformed, ingress_id=config.ingress_id,
            revision=1, digest="a" * 64,
            identity=module._identity(malformed),
        )


def test_v2_signature_is_cryptographically_domain_separated_from_v1(tmp_path):
    """Legacy v1 canonical signed bytes must never verify as v2 authority."""
    from shards_kernel.integrations.mtls_ingress import canonical_ingress_policy

    env, _, signed_v2, _, _ = _versioned(tmp_path)
    modern = canonical_ingress_policy(signed_v2)
    legacy = canonical_ingress_policy(env["policy"])
    assert modern.startswith(b"SHARDS-MTLS-INGRESS-V2\x00")
    assert legacy.startswith(b"SHARDS-MTLS-INGRESS-V1\x00")
    assert not modern.startswith(b"SHARDS-MTLS-INGRESS-V1\x00")

    forged_v2 = dict(signed_v2)
    forged_v2["signature_hex"] = env["ingress_key"].sign(
        b"SHARDS-MTLS-INGRESS-V1\x00"
        + modern[len(b"SHARDS-MTLS-INGRESS-V2\x00"):]
    ).hex()
    with pytest.raises(ValueError, match="signature"):
        verify_ingress_policy(
            forged_v2,
            pinned_public_key_hex=env["pinned"],
            now_ms=int(time.time() * 1000),
        )
    # Existing properly signed v1 loopback configurations remain readable.
    valid_v1 = verify_ingress_policy(
        env["policy"],
        pinned_public_key_hex=env["pinned"],
        now_ms=int(time.time() * 1000),
    )
    assert valid_v1.revision == 0


def test_revision_is_not_advanced_when_new_listener_cannot_bind(tmp_path):
    """Rejected port binding must leave the previously trusted revision intact."""
    import socket

    env, raw, _, config, path = _versioned(tmp_path)
    now = int(time.time() * 1000)
    newer = sign_mtls_ingress_policy(
        raw, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=2,
    )
    v2 = verify_ingress_policy(
        newer, pinned_public_key_hex=env["pinned"], now_ms=now,
    )
    server = MTLSIngressServer(v2)

    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind((v2.listen_host, v2.listen_port))
    occupied.listen(1)
    try:
        with pytest.raises(OSError):
            server.start(blocking=False)
        assert server._server is None
        with sqlite3.connect(path) as db:
            assert db.execute(
                "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
                (config.ingress_id,),
            ).fetchone() == (1,)
    finally:
        occupied.close()

    server.start(blocking=False)
    try:
        server._verify_policy_checkpoint()
        with sqlite3.connect(path) as db:
            assert db.execute(
                "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
                (config.ingress_id,),
            ).fetchone() == (2,)
    finally:
        server.stop()


def test_tls_initialization_failure_cannot_advance_revision(tmp_path, monkeypatch):
    """Invalid TLS setup must not burn a signed revision before bind."""
    from shards_kernel.integrations import mtls_ingress as module

    env, raw, _, config, path = _versioned(tmp_path)
    now = int(time.time() * 1000)
    newer = sign_mtls_ingress_policy(
        raw, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=2,
    )
    v2 = verify_ingress_policy(
        newer, pinned_public_key_hex=env["pinned"], now_ms=now,
    )

    def cannot_load_tls(_config):
        raise OSError("temporary test TLS load failure")

    monkeypatch.setattr(module, "_tls_context", cannot_load_tls)
    with pytest.raises(OSError, match="TLS load failure"):
        MTLSIngressServer(v2)
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
            (config.ingress_id,),
        ).fetchone() == (1,)


def test_checkpoint_preflight_is_read_only_and_blocks_untrusted_activation(tmp_path):
    """An instance cannot act under a newer policy until start() activates it."""
    env, raw, _, config, path = _versioned(tmp_path)
    now = int(time.time() * 1000)
    new_policy = sign_mtls_ingress_policy(
        raw, env["ingress_key"], issued_at_ms=now - 1000,
        expires_at_ms=now + 600_000, revision=2,
    )
    v2 = verify_ingress_policy(
        new_policy, pinned_public_key_hex=env["pinned"], now_ms=now,
    )
    server = MTLSIngressServer(v2)
    with pytest.raises(ValueError, match="no longer matches"):
        server._verify_policy_checkpoint()
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT revision FROM ingress_policy_checkpoint WHERE ingress_id=?",
            (config.ingress_id,),
        ).fetchone() == (1,)
