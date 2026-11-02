"""Signed operator policy: public trust, expiry, tampering and anti-rollback."""

import json
import time
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.signed_policy import (
    checkpoint_signed_policy,
    load_signed_policy,
    verify_signed_policy,
)
from shards_kernel.issuer import sign_operator_policy


def _raw_config(tmp_path):
    issuer = Ed25519PrivateKey.generate()
    return {
        "version": 1,
        "kernel_id": "signed-service",
        "actor": "agent-one",
        "tools": ["echo"],
        "issuer_keys": [{
            "key_id": "permit-key-1",
            "issuer": "permit-operator",
            "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": 8765,
    }


def _signed(tmp_path, signing_key=None, *, revision=1, now_ms=None):
    key = signing_key or Ed25519PrivateKey.generate()
    now = int(time.time() * 1000) if now_ms is None else now_ms
    envelope = sign_operator_policy(
        _raw_config(tmp_path), key, revision=revision,
        issued_at_ms=now - 10_000, expires_at_ms=now + 600_000,
    )
    return envelope, key, now


def _verify(envelope, key, now):
    return verify_signed_policy(
        envelope,
        trusted_public_key_hex=key.public_key().public_bytes_raw().hex(),
        current_time_ms=now,
    )


def test_valid_detached_trust_root_signed_policy_and_checkpoint(tmp_path):
    envelope, signing_key, now = _signed(tmp_path)
    result = _verify(envelope, signing_key, now)
    assert result.revision == 1
    assert result.config.kernel_id == "signed-service"
    assert len(result.digest) == 64
    assert result.expires_at_ms > now
    checkpoint_signed_policy(result)
    checkpoint_signed_policy(result)
    assert (tmp_path / "audit.sqlite3").exists()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(envelope))
    assert load_signed_policy(
        str(path),
        trusted_public_key_hex=signing_key.public_key().public_bytes_raw().hex(),
        current_time_ms=now,
    ) == result
    assert "private" not in path.read_text()


@pytest.mark.parametrize(
    "field, value",
    [
        ("actor", "another-agent"),
        ("port", 9999),
        ("tools", ["echo", "add"]),
        ("kernel_id", "another-kernel"),
        ("audit_db", "/tmp/attacker.sqlite3"),
    ],
)
def test_signed_config_modification_never_validates(tmp_path, field, value):
    envelope, signing_key, now = _signed(tmp_path)
    changed = deepcopy(envelope)
    changed["config"][field] = value
    with pytest.raises(ValueError):
        _verify(changed, signing_key, now)


def test_wrong_trust_key_signature_and_missing_key_denied(tmp_path):
    envelope, signing_key, now = _signed(tmp_path)
    attacker = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="signature"):
        _verify(envelope, attacker, now)
    with pytest.raises(ValueError, match="public key"):
        verify_signed_policy(envelope, trusted_public_key_hex="", current_time_ms=now)
    forged = deepcopy(envelope)
    forged["signature_hex"] = "00" * 64
    with pytest.raises(ValueError, match="signature"):
        _verify(forged, signing_key, now)
    tampered_revision = deepcopy(envelope)
    tampered_revision["revision"] = 2
    with pytest.raises(ValueError, match="signature"):
        _verify(tampered_revision, signing_key, now)


def test_expired_future_and_oversized_validity_fail_closed(tmp_path):
    envelope, signing_key, now = _signed(tmp_path)
    with pytest.raises(ValueError, match="not currently valid"):
        _verify(envelope, signing_key, now + 1_000_000)
    with pytest.raises(ValueError, match="not currently valid"):
        _verify(envelope, signing_key, now - 100_000)
    with pytest.raises(ValueError, match="validity"):
        sign_operator_policy(
            _raw_config(tmp_path), signing_key,
            revision=1, issued_at_ms=now, expires_at_ms=now + 31 * 86_400_000,
        )
    with pytest.raises(ValueError, match="revision"):
        sign_operator_policy(
            _raw_config(tmp_path), signing_key,
            revision=True, issued_at_ms=now, expires_at_ms=now + 86_400_000,
        )


def test_policy_revision_rollback_and_reuse_detection(tmp_path):
    signer = Ed25519PrivateKey.generate()
    e1, _, now = _signed(tmp_path, signer, revision=1)
    checkpoint_signed_policy(_verify(e1, signer, now))
    e2, _, _ = _signed(tmp_path, signer, revision=2, now_ms=now)
    checkpoint_signed_policy(_verify(e2, signer, now))
    checkpoint_signed_policy(_verify(e2, signer, now))
    with pytest.raises(ValueError, match="rollback"):
        checkpoint_signed_policy(_verify(e1, signer, now))
    same_number = sign_operator_policy(
        dict(_raw_config(tmp_path), port=8888), signer, revision=2,
        issued_at_ms=now - 10_000, expires_at_ms=now + 600_000,
    )
    with pytest.raises(ValueError, match="rollback"):
        checkpoint_signed_policy(_verify(same_number, signer, now))


def test_loader_rejects_duplicate_json_numeric_constants_and_symlink(tmp_path):
    envelope, signing_key, now = _signed(tmp_path)
    path = tmp_path / "config.json"
    path.write_text('{"schema":"x","schema":"y"}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_signed_policy(str(path), trusted_public_key_hex="00" * 32, current_time_ms=now)
    path.write_text('{"schema":NaN}')
    with pytest.raises(ValueError, match="Non-finite"):
        load_signed_policy(str(path), trusted_public_key_hex="00" * 32, current_time_ms=now)
    path.write_text('{"schema":1.2}')
    with pytest.raises(ValueError, match="Floating"):
        load_signed_policy(str(path), trusted_public_key_hex="00" * 32, current_time_ms=now)
    path.write_text(json.dumps(envelope))
    link = tmp_path / "policy-link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="non-symlink"):
        load_signed_policy(
            str(link), trusted_public_key_hex=signing_key.public_key().public_bytes_raw().hex(),
            current_time_ms=now,
        )
    path.write_text("z" * (96 * 1024 + 1))
    with pytest.raises(ValueError, match="too large"):
        load_signed_policy(
            str(path), trusted_public_key_hex=signing_key.public_key().public_bytes_raw().hex(),
            current_time_ms=now,
        )


def test_unsigned_local_service_requires_explicit_flag(tmp_path, capsys, monkeypatch):
    from shards_kernel.cli.service import run_service

    monkeypatch.delenv("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX", raising=False)
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(_raw_config(tmp_path)))
    assert run_service(str(path)) == 2
    assert "refused startup" in capsys.readouterr().out
