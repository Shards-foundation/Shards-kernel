"""Cryptographic, rollback and malformed-input tests for offline audit anchors.

These unit tests use real Ed25519 signatures and no service, database, private
key files or network. They do not establish independent off-host custody.
"""

import base64
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.distributed.checkpoint import (
    CheckpointIntegrityError,
    GENESIS_CHECKPOINT_DIGEST,
    SignedAuthorityCheckpoint,
    sign_checkpoint,
    verify_checkpoint,
    verify_checkpoint_chain,
    verify_snapshot_against_checkpoint,
)


@pytest.fixture
def identity():
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes_raw()
    return signer, {"offline-operator": public}


def make_checkpoint(identity, *, sequence=5, root="a" * 64,
                    previous=None, issued_at_ms=1000, environment="staging-a"):
    return sign_checkpoint(
        sequence=sequence, root=root, environment=environment,
        issued_at_ms=issued_at_ms, key_id="offline-operator",
        private_key=identity[0], previous=previous,
    )


def verify(cp, identity, **kwargs):
    return verify_checkpoint(
        cp, trusted_keys=identity[1], expected_environment="staging-a", **kwargs,
    )


def test_signed_checkpoint_roundtrip_and_pinned_verification(identity):
    cp = make_checkpoint(identity)
    assert cp.previous_digest == GENESIS_CHECKPOINT_DIGEST
    assert len(cp.digest()) == 64
    verified = SignedAuthorityCheckpoint.from_json(cp.as_json())
    assert verified == cp
    assert verified.digest() == cp.digest()
    assert verify(verified, identity) is None
    assert '"signature"' in cp.as_json()


def test_signature_and_root_tampering_denied(identity):
    cp = make_checkpoint(identity)
    for bad in (
        replace(cp, root="b" * 64),
        replace(cp, sequence=6),
        replace(cp, signature=base64.b64encode(b"X" * 64).decode()),
        replace(cp, key_id="attacker"),
    ):
        with pytest.raises(CheckpointIntegrityError):
            verify(bad, identity)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(CheckpointIntegrityError, match="signature"):
        verify_checkpoint(
            cp, trusted_keys={"offline-operator": other},
            expected_environment="staging-a",
        )
    with pytest.raises(CheckpointIntegrityError, match="Untrusted"):
        verify_checkpoint(
            cp, trusted_keys={}, expected_environment="staging-a",
        )


def test_environment_sequence_and_key_trust_fail_closed(identity):
    cp = make_checkpoint(identity)
    with pytest.raises(CheckpointIntegrityError, match="environment mismatch"):
        verify_checkpoint(
            cp, trusted_keys=identity[1], expected_environment="production-a",
        )
    with pytest.raises(CheckpointIntegrityError, match="pinned minimum"):
        verify(cp, identity, minimum_sequence=6)
    with pytest.raises(ValueError, match="minimum_sequence"):
        verify(cp, identity, minimum_sequence=True)
    with pytest.raises(ValueError, match="minimum_sequence"):
        verify(cp, identity, minimum_sequence=-1)
    with pytest.raises(CheckpointIntegrityError, match="Untrusted"):
        verify_checkpoint(
            cp, trusted_keys={"offline-operator": b"short"},
            expected_environment="staging-a",
        )


@pytest.mark.parametrize("changes,match", [
    ({"version": 2}, "version"),
    ({"version": True}, "version"),
    ({"environment": ""}, "environment"),
    ({"environment": "untrusted environment"}, "environment"),
    ({"key_id": ""}, "key_id"),
    ({"sequence": -1}, "sequence"),
    ({"sequence": True}, "sequence"),
    ({"root": "A" * 64}, "root"),
    ({"root": "broken"}, "root"),
    ({"issued_at_ms": 0}, "timestamp"),
    ({"issued_at_ms": True}, "timestamp"),
    ({"previous_digest": "invalid"}, "previous"),
    ({"signature": "!"}, "signature"),
    ({"signature": base64.b64encode(b"too short").decode()}, "signature length"),
])
def test_checkpoint_schema_rejects_invalid_fields(identity, changes, match):
    cp = replace(make_checkpoint(identity), **changes)
    with pytest.raises(CheckpointIntegrityError, match=match):
        cp.validate()


def test_strict_json_parser_rejects_extra_missing_and_bad_json(identity):
    cp = make_checkpoint(identity)
    payload = json.loads(cp.as_json())
    for value in (
        "{}",
        "[]",
        "not json",
        json.dumps({**payload, "trusted_public_key": "attacker"}),
        json.dumps({k: v for k, v in payload.items() if k != "environment"}),
    ):
        with pytest.raises(CheckpointIntegrityError):
            SignedAuthorityCheckpoint.from_json(value)
    with pytest.raises(CheckpointIntegrityError, match="text"):
        SignedAuthorityCheckpoint.from_json(b"bytes")


def test_key_type_and_monotonic_signer_guards(identity):
    with pytest.raises(TypeError, match="Ed25519PrivateKey"):
        sign_checkpoint(
            sequence=1, root="a" * 64, environment="staging-a",
            issued_at_ms=1000, key_id="offline-operator", private_key=b"not a key",
        )
    previous = make_checkpoint(identity)
    with pytest.raises(CheckpointIntegrityError, match="sequence must advance"):
        make_checkpoint(identity, previous=previous, sequence=5, issued_at_ms=2000)
    with pytest.raises(CheckpointIntegrityError, match="timestamp must advance"):
        make_checkpoint(identity, previous=previous, sequence=6, issued_at_ms=1000)
    with pytest.raises(CheckpointIntegrityError, match="environment changed"):
        make_checkpoint(
            identity, previous=previous, sequence=6,
            issued_at_ms=2000, environment="other-env",
        )


def test_checkpoint_chain_rotates_keys_and_pins_last_minimum(identity):
    cp1 = make_checkpoint(identity)
    key2 = Ed25519PrivateKey.generate()
    key2_name = "rotated-offline-key"
    cp2 = sign_checkpoint(
        sequence=9, root="b" * 64, environment="staging-a",
        issued_at_ms=2000, key_id=key2_name,
        private_key=key2, previous=cp1,
    )
    trusted = {
        **identity[1],
        key2_name: key2.public_key().public_bytes_raw(),
    }
    assert cp2.previous_digest == cp1.digest()
    assert verify_checkpoint_chain(
        [cp1, cp2], trusted_keys=trusted,
        expected_environment="staging-a", minimum_sequence=9,
    ) == cp2
    with pytest.raises(CheckpointIntegrityError, match="pinned minimum"):
        verify_checkpoint_chain(
            [cp1, cp2], trusted_keys=trusted,
            expected_environment="staging-a", minimum_sequence=10,
        )
    with pytest.raises(CheckpointIntegrityError, match="Missing or reordered"):
        verify_checkpoint_chain(
            [cp2], trusted_keys=trusted, expected_environment="staging-a",
        )
    with pytest.raises(CheckpointIntegrityError, match="Missing or reordered"):
        verify_checkpoint_chain(
            [cp2, cp1], trusted_keys=trusted, expected_environment="staging-a",
        )
    with pytest.raises(CheckpointIntegrityError, match="No externally"):
        verify_checkpoint_chain(
            [], trusted_keys=trusted, expected_environment="staging-a",
        )


def test_snapshot_rollback_and_unproved_future_history_denied(identity):
    cp = make_checkpoint(identity)
    expected = dict(
        checkpoint=cp, trusted_keys=identity[1],
        expected_environment="staging-a",
    )
    assert verify_snapshot_against_checkpoint(
        sequence=cp.sequence, root=cp.root, **expected,
    ) is None
    with pytest.raises(CheckpointIntegrityError, match="rolled back"):
        verify_snapshot_against_checkpoint(
            sequence=cp.sequence - 1, root=cp.root, **expected,
        )
    with pytest.raises(CheckpointIntegrityError, match="Newer history"):
        verify_snapshot_against_checkpoint(
            sequence=cp.sequence + 1, root=cp.root, **expected,
        )
    with pytest.raises(CheckpointIntegrityError, match="root does not match"):
        verify_snapshot_against_checkpoint(
            sequence=cp.sequence, root="b" * 64, **expected,
        )
    with pytest.raises(CheckpointIntegrityError, match="signature"):
        verify_snapshot_against_checkpoint(
            sequence=cp.sequence, root=cp.root,
            checkpoint=replace(cp, root="c" * 64),
            trusted_keys=identity[1], expected_environment="staging-a",
        )


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("environment", None),
        ("environment", 42),
        ("environment", b"staging-a"),
        ("environment", ["staging-a"]),
        ("key_id", None),
        ("key_id", 42),
        ("key_id", b"offline-operator"),
        ("key_id", {"key": "offline-operator"}),
    ],
)
def test_nonstring_identity_fields_fail_with_integrity_exception(
    identity, field, invalid,
):
    signed = make_checkpoint(identity)
    tampered = replace(signed, **{field: invalid})
    with pytest.raises(CheckpointIntegrityError, match="Malformed checkpoint"):
        tampered.validate()
    # Parsing externally supplied JSON must have the same strict contract.
    payload = json.loads(signed.as_json())
    if isinstance(invalid, bytes):
        payload[field] = invalid.decode()
        # Bytes are not a representable JSON scalar: direct object coverage
        # above enforces the Python caller boundary.
    else:
        payload[field] = invalid
        with pytest.raises(CheckpointIntegrityError, match="Malformed checkpoint"):
            SignedAuthorityCheckpoint.from_json(json.dumps(payload))


def test_duplicate_json_fields_are_not_silently_interpreted(identity):
    cp = make_checkpoint(identity)
    valid_json = cp.as_json()
    duplicate = valid_json[:-1] + ',"environment":"staging-a"}'
    with pytest.raises(CheckpointIntegrityError, match="Duplicate checkpoint"):
        SignedAuthorityCheckpoint.from_json(duplicate)
    assert SignedAuthorityCheckpoint.from_json(valid_json) == cp


@pytest.mark.parametrize("minimum", [True, -1, "1", None])
def test_chain_rejects_invalid_pinned_minimum_type(identity, minimum):
    cp = make_checkpoint(identity)
    with pytest.raises(ValueError, match="minimum_sequence"):
        verify_checkpoint_chain(
            [cp], trusted_keys=identity[1],
            expected_environment="staging-a", minimum_sequence=minimum,
        )
