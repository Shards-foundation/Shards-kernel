"""Signed v2 mTLS policy: local revision anti-rollback, restart and live denial."""

from __future__ import annotations

import copy
import os
import sqlite3
import subprocess
import sys
import textwrap
import time

import pytest

from shards_kernel.integrations.mtls_checkpoint import (
    checkpoint_ingress_revision, verify_ingress_checkpoint,
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
    upgraded._verify_policy_checkpoint()
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
    MTLSIngressServer(config)  # A restart can recreate a deleted local row.
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


def test_optimised_interpreter_cannot_disable_signed_checkpoint_checks():
    """Prove runtime authority validation still executes under Python -O."""
    script = textwrap.dedent("""
        from types import SimpleNamespace
        from shards_kernel.integrations.mtls_ingress import MTLSIngressServer

        ingress = object.__new__(MTLSIngressServer)
        ingress.config = SimpleNamespace(
            revision=1, ingress_id=None,
            policy_digest=None, checkpoint_db_file=None,
        )
        ingress._checkpoint_identity = None
        try:
            ingress._verify_policy_checkpoint()
        except ValueError as exc:
            if str(exc) == "Missing signed ingress checkpoint authority":
                raise SystemExit(0)
        raise SystemExit(2)
    """)
    result = subprocess.run(
        [sys.executable, "-O", "-c", script],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
