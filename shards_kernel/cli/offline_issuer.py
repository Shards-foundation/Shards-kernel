"""Operator-reviewed offline permit issuance.

The approver and issuer are independent Ed25519 principals. The kernel
receives ONLY the issuer's public key, never either private key. This
module has no server, MCP tool, network API or agent-facing signing path.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from shards_kernel.permits import (
    PermitToken,
    canonical_permit_bytes,
    compute_permit_id,
)

_APPROVAL_DOMAIN = b"SHARDS-OFFLINE-APPROVAL-V1\x00"
_MAX_APPROVAL_MS = 10 * 60 * 1000
_MAX_PERMIT_MS = 15 * 60 * 1000
_APPROVAL_FIELDS = {
    "schema",
    "reviewer",
    "permit_sha256",
    "permit_id",
    "approved_at_ms",
    "expires_at_ms",
    "signature_hex",
}


def validate_narrow_draft(draft: PermitToken) -> None:
    """Refuse ambiguous or broad privileges in this reference issuer."""
    if draft.version != 2 or draft.algorithm != "Ed25519" or draft.signature:
        raise ValueError("Only unsigned v2 Ed25519 permits are issuable")
    if draft.permit_id != compute_permit_id(draft):
        raise ValueError("Draft permit ID does not match canonical content")
    if draft.max_executions != 1:
        raise ValueError("Offline issuer requires a single execution")
    if not 0 < draft.valid_until_ms - draft.valid_from_ms <= _MAX_PERMIT_MS:
        raise ValueError("Offline permit validity must be at most 15 minutes")
    for item in (draft.subject, draft.audience, draft.action, draft.issuer, draft.key_id):
        if not item or "*" in item or item.strip() != item:
            raise ValueError("Issuer refuses wildcard or ambiguous permit identity")
    if draft.action not in {"echo", "add"}:
        raise ValueError("Offline reference issuer allows only built-in echo/add")


def _approved_payload(approval: dict[str, Any]) -> bytes:
    """Exact domain-separated signed representation of approval metadata."""
    fields = {key: approval[key] for key in (
        "schema", "reviewer", "permit_sha256", "permit_id",
        "approved_at_ms", "expires_at_ms",
    )}
    return _APPROVAL_DOMAIN + json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _draft_digest(draft: PermitToken) -> str:
    return hashlib.sha256(canonical_permit_bytes(draft)).hexdigest()


def sign_operator_approval(
    draft: PermitToken,
    approver_private_key: Any,
    *,
    reviewer: str,
    approved_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    """Operator-approved *exact* draft, signed by an approval-only private key.

    Run in a separate trusted operator process. The approval binds the
    entire unsigned draft digest, including subject, tool, params, nonce,
    issuer, audience and validity, rather than trusting an agent description.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    validate_narrow_draft(draft)
    if not isinstance(approver_private_key, Ed25519PrivateKey):
        raise TypeError("Ed25519 approver private key required")
    if not isinstance(reviewer, str) or not reviewer or "*" in reviewer or reviewer.strip() != reviewer:
        raise ValueError("Reviewer must be a concrete operator identity")
    if (
        type(approved_at_ms) is not int
        or type(expires_at_ms) is not int
        or approved_at_ms < 0
        or not 0 < expires_at_ms - approved_at_ms <= _MAX_APPROVAL_MS
    ):
        raise ValueError("Approval lifetime must be at most ten minutes")
    if not draft.valid_from_ms <= approved_at_ms <= draft.valid_until_ms:
        raise ValueError("Approval time outside draft permit validity window")
    approval = {
        "schema": "shards.operator-approval.v1",
        "reviewer": reviewer,
        "permit_sha256": _draft_digest(draft),
        "permit_id": draft.permit_id,
        "approved_at_ms": approved_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    approval["signature_hex"] = approver_private_key.sign(
        _approved_payload(approval)
    ).hex()
    return approval


def _check_approval_fields(approval: Any) -> dict[str, Any]:
    if not isinstance(approval, dict) or set(approval) != _APPROVAL_FIELDS:
        raise ValueError("Approval has unknown or missing fields")
    if approval["schema"] != "shards.operator-approval.v1":
        raise ValueError("Unsupported approval schema")
    reviewer = approval["reviewer"]
    if not isinstance(reviewer, str) or not reviewer or "*" in reviewer or reviewer.strip() != reviewer:
        raise ValueError("Approval reviewer invalid")
    for field in ("approved_at_ms", "expires_at_ms"):
        if type(approval[field]) is not int or approval[field] < 0:
            raise ValueError("Approval time must be a nonnegative UTC integer")
    if not 0 < approval["expires_at_ms"] - approval["approved_at_ms"] <= _MAX_APPROVAL_MS:
        raise ValueError("Approval lifetime exceeds ten minutes")
    for field, length in (("permit_sha256", 64), ("permit_id", 64), ("signature_hex", 128)):
        value = approval[field]
        if not isinstance(value, str) or len(value) != length or any(
            c not in "0123456789abcdef" for c in value
        ):
            raise ValueError("Approval digest or signature format invalid")
    return approval


def issue_approved_permit(
    draft: PermitToken,
    approval: dict[str, Any],
    issuer_private_key: Any,
    approver_public_key_bytes: bytes,
    *,
    now_ms: int,
    expected_issuer: str,
    expected_key_id: str,
) -> PermitToken:
    """Only sign after a distinct, trusted approver signs the exact draft."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from shards_kernel.issuer import sign_v2_permit

    validate_narrow_draft(draft)
    record = _check_approval_fields(approval)
    if not isinstance(issuer_private_key, Ed25519PrivateKey):
        raise TypeError("Ed25519 issuer private key required")
    if not isinstance(approver_public_key_bytes, bytes) or len(approver_public_key_bytes) != 32:
        raise ValueError("Pinned approver public key must be 32 bytes")
    if issuer_private_key.public_key().public_bytes_raw() == approver_public_key_bytes:
        raise ValueError("Separation of duties: issuer and approver key must differ")
    if not expected_issuer or not expected_key_id:
        raise ValueError("Expected issuer identity and key ID required")
    if draft.issuer != expected_issuer or draft.key_id != expected_key_id:
        raise ValueError("Draft issuer identity or key ID does not match operator expectation")
    if (
        type(now_ms) is not int
        or now_ms < record["approved_at_ms"]
        or now_ms > record["expires_at_ms"]
        or now_ms < draft.valid_from_ms
        or now_ms > draft.valid_until_ms
    ):
        raise ValueError("Approval or permit is expired or not yet valid")
    if record["permit_sha256"] != _draft_digest(draft) or record["permit_id"] != draft.permit_id:
        raise ValueError("Approved draft does not match exact permit content")
    try:
        Ed25519PublicKey.from_public_bytes(approver_public_key_bytes).verify(
            bytes.fromhex(record["signature_hex"]), _approved_payload(record)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Approval signature invalid") from exc
    return sign_v2_permit(draft, issuer_private_key)
