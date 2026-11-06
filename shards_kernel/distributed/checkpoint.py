"""Off-host verifiable Ed25519 checkpoints for the shared authority journal.

This module never contacts PostgreSQL, stores keys or claims a checkpoint is
independently anchored. Operators must retain signed checkpoints and pinned
verification keys in a separate trust domain. The database itself is never a
trusted source for the verifier's keyring or its minimum accepted checkpoint.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_VERSION = 1
_DOMAIN = b"SHARDS-AUTHORITY-CHECKPOINT-V1\x00"
GENESIS_CHECKPOINT_DIGEST = "0" * 64
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "version", "environment", "sequence", "root", "issued_at_ms",
    "key_id", "previous_digest", "signature",
})


class CheckpointIntegrityError(RuntimeError):
    """A checkpoint is missing, altered, untrusted, stale or inconsistent."""


@dataclass(frozen=True)
class SignedAuthorityCheckpoint:
    """Signed, canonical audit root; it is not an off-host storage receipt."""

    version: int
    environment: str
    sequence: int
    root: str
    issued_at_ms: int
    key_id: str
    previous_digest: str
    signature: str

    def _validate_identity(self) -> None:
        for field in ("environment", "key_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise CheckpointIntegrityError("Malformed checkpoint " + field)

    def _validate_numbers(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise CheckpointIntegrityError("Invalid checkpoint sequence")
        if type(self.issued_at_ms) is not int or self.issued_at_ms <= 0:
            raise CheckpointIntegrityError("Invalid checkpoint timestamp")

    def _validate_hashes(self) -> None:
        if not isinstance(self.root, str) or _HASH.fullmatch(self.root) is None:
            raise CheckpointIntegrityError("Malformed checkpoint root")
        if (
            not isinstance(self.previous_digest, str)
            or _HASH.fullmatch(self.previous_digest) is None
        ):
            raise CheckpointIntegrityError("Malformed previous checkpoint digest")

    def _validate_signature(self) -> None:
        if not isinstance(self.signature, str):
            raise CheckpointIntegrityError("Malformed checkpoint signature")
        try:
            decoded = base64.b64decode(self.signature, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise CheckpointIntegrityError("Malformed checkpoint signature") from exc
        if len(decoded) != 64:
            raise CheckpointIntegrityError("Invalid checkpoint signature length")

    def validate(self) -> None:
        """Validate all signed fields before use or serialisation."""
        if type(self.version) is not int or self.version != _VERSION:
            raise CheckpointIntegrityError("Unsupported checkpoint version")
        self._validate_identity()
        self._validate_numbers()
        self._validate_hashes()
        self._validate_signature()

    def _payload(self) -> dict[str, Any]:
        return {
            "version": self.version, "environment": self.environment,
            "sequence": self.sequence, "root": self.root,
            "issued_at_ms": self.issued_at_ms, "key_id": self.key_id,
            "previous_digest": self.previous_digest,
        }

    def signing_bytes(self) -> bytes:
        """Domain-separated canonical representation, signed without base64."""
        return _DOMAIN + json.dumps(
            self._payload(), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("ascii")

    def digest(self) -> str:
        """Commit to the entire checkpoint including its cryptographic proof."""
        self.validate()
        return hashlib.sha256(
            self.signing_bytes()
            + b"\x00"
            + base64.b64decode(self.signature, validate=True)
        ).hexdigest()

    def as_json(self) -> str:
        self.validate()
        return json.dumps(
            {**self._payload(), "signature": self.signature},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, source: str) -> "SignedAuthorityCheckpoint":
        if not isinstance(source, str):
            raise CheckpointIntegrityError("Checkpoint JSON must be text")
        try:
            parsed = json.loads(source)
        except (TypeError, ValueError) as exc:
            raise CheckpointIntegrityError("Malformed checkpoint JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != _FIELDS:
            raise CheckpointIntegrityError("Unexpected or missing checkpoint fields")
        obj = cls(**parsed)
        obj.validate()
        return obj


def sign_checkpoint(
    *,
    sequence: int,
    root: str,
    environment: str,
    issued_at_ms: int,
    key_id: str,
    private_key: Any,
    previous: SignedAuthorityCheckpoint | None = None,
) -> SignedAuthorityCheckpoint:
    """Sign a verified authority root with an operator-managed Ed25519 key.

    The signer must obtain sequence/root from a verified PostgreSQL snapshot.
    This function cannot establish that its caller supplied an authentic
    snapshot or that private key custody is independent of the runtime.
    """
    if previous is not None:
        previous.validate()
        if environment != previous.environment:
            raise CheckpointIntegrityError("Checkpoint environment changed")
        if type(sequence) is not int or sequence <= previous.sequence:
            raise CheckpointIntegrityError("Checkpoint sequence must advance")
        if type(issued_at_ms) is not int or issued_at_ms <= previous.issued_at_ms:
            raise CheckpointIntegrityError("Checkpoint timestamp must advance")
    unsigned = SignedAuthorityCheckpoint(
        version=_VERSION,
        environment=environment, sequence=sequence, root=root,
        issued_at_ms=issued_at_ms, key_id=key_id,
        previous_digest=(
            previous.digest() if previous is not None
            else GENESIS_CHECKPOINT_DIGEST
        ),
        signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    unsigned.validate()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Offline checkpoint signer must be an Ed25519PrivateKey")
    signature = private_key.sign(unsigned.signing_bytes())
    signed = SignedAuthorityCheckpoint(
        **unsigned._payload(), signature=base64.b64encode(signature).decode("ascii"),
    )
    signed.validate()
    return signed


def verify_checkpoint(
    checkpoint: SignedAuthorityCheckpoint,
    *,
    trusted_keys: Mapping[str, bytes],
    expected_environment: str,
    minimum_sequence: int = 0,
) -> None:
    """Verify against an explicitly pinned, out-of-band public-key mapping."""
    checkpoint.validate()
    if checkpoint.environment != expected_environment:
        raise CheckpointIntegrityError("Checkpoint environment mismatch")
    if type(minimum_sequence) is not int or minimum_sequence < 0:
        raise ValueError("minimum_sequence must be a nonnegative integer")
    if checkpoint.sequence < minimum_sequence:
        raise CheckpointIntegrityError("Checkpoint rollback below pinned minimum")
    trusted_key = trusted_keys.get(checkpoint.key_id)
    if not isinstance(trusted_key, bytes) or len(trusted_key) != 32:
        raise CheckpointIntegrityError("Untrusted checkpoint signing key")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(
            base64.b64decode(checkpoint.signature, validate=True),
            checkpoint.signing_bytes(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise CheckpointIntegrityError("Checkpoint signature verification failed") from exc


def verify_checkpoint_chain(
    checkpoints: Sequence[SignedAuthorityCheckpoint],
    *,
    trusted_keys: Mapping[str, bytes],
    expected_environment: str,
    minimum_sequence: int = 0,
) -> SignedAuthorityCheckpoint:
    """Verify a complete externally retained checkpoint chain, oldest first."""
    if not checkpoints:
        raise CheckpointIntegrityError("No externally retained checkpoints")
    previous: SignedAuthorityCheckpoint | None = None
    for checkpoint in checkpoints:
        verify_checkpoint(
            checkpoint, trusted_keys=trusted_keys,
            expected_environment=expected_environment,
            minimum_sequence=0,
        )
        expected_previous = (
            previous.digest() if previous is not None
            else GENESIS_CHECKPOINT_DIGEST
        )
        if checkpoint.previous_digest != expected_previous:
            raise CheckpointIntegrityError("Missing or reordered checkpoint")
        if previous is not None and (
            checkpoint.sequence <= previous.sequence
            or checkpoint.issued_at_ms <= previous.issued_at_ms
        ):
            raise CheckpointIntegrityError("Checkpoint chain sequence or time rollback")
        previous = checkpoint
    latest = checkpoints[-1]
    if latest.sequence < minimum_sequence:
        raise CheckpointIntegrityError("Checkpoint rollback below pinned minimum")
    return latest


def verify_snapshot_against_checkpoint(
    *,
    sequence: int,
    root: str,
    checkpoint: SignedAuthorityCheckpoint,
    trusted_keys: Mapping[str, bytes],
    expected_environment: str,
    minimum_sequence: int = 0,
) -> None:
    """Compare the live authority to an *independently verified* signed root.

    Never accept a caller-supplied unauthenticated checkpoint or derive trust
    keys from the database being checked. A newer database history must
    provide a separately verified historical inclusion witness.
    """
    verify_checkpoint(
        checkpoint,
        trusted_keys=trusted_keys,
        expected_environment=expected_environment,
        minimum_sequence=minimum_sequence,
    )
    if type(sequence) is not int or sequence < checkpoint.sequence:
        raise CheckpointIntegrityError("Authority database rolled back")
    if sequence != checkpoint.sequence:
        raise CheckpointIntegrityError("Newer history needs anchored inclusion proof")
    if root != checkpoint.root:
        raise CheckpointIntegrityError("Authority root does not match external anchor")
