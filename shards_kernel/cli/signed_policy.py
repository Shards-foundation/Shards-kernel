"""Offline operator policy verification: pinned Ed25519 trust and revision gates.

Only the public root key is supplied to this verifier. Never load a policy
signing private key into the Shards-Kernel operator service.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shards_kernel.cli.service import (
    OperatorServiceConfig,
    _fields,
    _reject_constant,
    _unique_pairs,
    parse_operator_config,
)

_DOMAIN = b"SHARDS-OPERATOR-POLICY-V1\x00"
_MAX_SIZE = 96 * 1024
_MAX_VALIDITY_MS = 30 * 24 * 60 * 60 * 1000


@dataclass(frozen=True)
class VerifiedPolicy:
    config: OperatorServiceConfig
    revision: int
    digest: str
    expires_at_ms: int


def canonical_policy_payload(envelope: dict[str, Any]) -> bytes:
    """Exact signed message; reject ambiguous JSON, floats and non-JSON input."""
    payload = {
        field: envelope[field]
        for field in ("schema", "revision", "issued_at_ms", "expires_at_ms", "config")
    }
    return _DOMAIN + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_float(_value: str) -> None:
    raise ValueError("Floating point values are not allowed in signed policy")


def _parse_envelope(envelope: Any) -> tuple[dict[str, Any], OperatorServiceConfig]:
    obj = _fields(
        envelope,
        {"schema", "revision", "issued_at_ms", "expires_at_ms", "config", "signature_hex"},
        "Signed policy",
    )
    if obj["schema"] != "shards.operator-policy.v1":
        raise ValueError("Unsupported signed policy schema")
    if type(obj["revision"]) is not int or obj["revision"] < 1:
        raise ValueError("Policy revision must be a positive integer")
    if any(
        type(obj[k]) is not int or obj[k] < 0
        for k in ("issued_at_ms", "expires_at_ms")
    ):
        raise ValueError("Signed policy validity timestamps must be non-negative integers")
    if not 0 < obj["expires_at_ms"] - obj["issued_at_ms"] <= _MAX_VALIDITY_MS:
        raise ValueError("Signed policy validity window must not exceed 30 days")
    signature = obj["signature_hex"]
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(c not in "0123456789abcdef" for c in signature)
    ):
        raise ValueError("Signature must be 128 lowercase hex characters")
    return obj, parse_operator_config(obj["config"])


def verify_signed_policy(
    envelope: Any, *, trusted_public_key_hex: str, current_time_ms: int
) -> VerifiedPolicy:
    """Verify policy signature, expiry and schema before any service startup."""
    obj, config = _parse_envelope(envelope)
    if (
        not isinstance(trusted_public_key_hex, str)
        or len(trusted_public_key_hex) != 64
        or any(c not in "0123456789abcdef" for c in trusted_public_key_hex)
    ):
        raise ValueError("Pinned policy public key must be 64 lowercase hex characters")
    if (
        type(current_time_ms) is not int
        or current_time_ms < obj["issued_at_ms"]
        or current_time_ms > obj["expires_at_ms"]
    ):
        raise ValueError("Signed policy is not currently valid")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    payload = canonical_policy_payload(obj)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            bytes.fromhex(obj["signature_hex"]), payload
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Signed policy signature is invalid") from exc
    return VerifiedPolicy(
        config=config,
        revision=obj["revision"],
        digest=hashlib.sha256(payload).hexdigest(),
        expires_at_ms=obj["expires_at_ms"],
    )


def load_signed_policy(
    path: str, *, trusted_public_key_hex: str, current_time_ms: int
) -> VerifiedPolicy:
    """Read a bounded non-symlink document, then authenticate it."""
    file = Path(path)
    if not file.is_file() or file.is_symlink():
        raise ValueError("Signed policy must be a regular non-symlink file")
    if file.stat().st_size > _MAX_SIZE:
        raise ValueError("Signed policy document is too large")
    with file.open("rb") as stream:
        contents = stream.read(_MAX_SIZE + 1)
    if len(contents) > _MAX_SIZE:
        raise ValueError("Signed policy document is too large")
    try:
        envelope = json.loads(
            contents.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid signed policy encoding") from exc
    return verify_signed_policy(
        envelope, trusted_public_key_hex=trusted_public_key_hex,
        current_time_ms=current_time_ms,
    )


def checkpoint_signed_policy(policy: VerifiedPolicy) -> None:
    """Reject previously accepted revisions using the local SQLite ledger DB.

    Call ONLY inside the same single-writer audit lock held through startup
    and process lifetime. SQLite state is *not* a tamper-proof external anchor.
    """
    db = policy.config.audit_db
    with sqlite3.connect(db) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS operator_policy_checkpoint (
                kernel_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                digest TEXT NOT NULL
            )"""
        )
        row = connection.execute(
            "SELECT revision, digest FROM operator_policy_checkpoint WHERE kernel_id=?",
            (policy.config.kernel_id,),
        ).fetchone()
        if row is not None and (
            policy.revision < row[0]
            or (policy.revision == row[0] and policy.digest != row[1])
        ):
            raise ValueError("Policy revision rollback or changed revision digest")
        if row is None:
            connection.execute(
                "INSERT INTO operator_policy_checkpoint VALUES (?, ?, ?)",
                (policy.config.kernel_id, policy.revision, policy.digest),
            )
        elif policy.revision > row[0]:
            connection.execute(
                "UPDATE operator_policy_checkpoint SET revision=?, digest=? WHERE kernel_id=?",
                (policy.revision, policy.digest, policy.config.kernel_id),
            )
