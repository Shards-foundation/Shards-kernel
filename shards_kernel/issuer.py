"""Trusted permit issuance process: NEVER expose private keys as MCP tools.

This module deliberately lives apart from BaseKernel. An operator service
holds the private Ed25519 key; the kernel receives only its 32-byte public key.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from shards_kernel.permits import PermitToken, canonical_permit_bytes, compute_permit_id

DOMAIN = b"SHARDS-PERMIT-ED25519-V2\x00"


def sign_v2_permit(unsigned: PermitToken, private_key: Any) -> PermitToken:
    """Sign a prepared v2 permit with a cryptography Ed25519PrivateKey.

    The private key must be supplied by the trusted issuer process. It must
    not be stored in a kernel verifier, agent environment or model prompt.
    """
    if unsigned.version != 2 or unsigned.algorithm != "Ed25519":
        raise ValueError("Only v2 Ed25519 permits can be signed here")
    if unsigned.signature:
        raise ValueError("Refusing to sign a permit that already has a signature")
    if unsigned.permit_id != compute_permit_id(unsigned):
        raise ValueError("Permit ID does not match canonical payload")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Only Ed25519PrivateKey is accepted")
    sig = private_key.sign(DOMAIN + canonical_permit_bytes(unsigned))
    return replace(unsigned, signature=sig.hex())


def sign_operator_policy(
    config: dict[str, Any],
    private_key: Any,
    *,
    revision: int,
    issued_at_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    """Create a signed policy envelope within a trusted operator signing process.

    This function is for an OFFLINE issuer, not an MCP-accessible service.
    Never provision the signing private key onto the Shards-Kernel runtime.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from shards_kernel.cli.signed_policy import canonical_policy_payload

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Only Ed25519PrivateKey is accepted")
    if not isinstance(config, dict):
        raise ValueError("Signed configuration must be an object")
    if type(revision) is not int or revision < 1:
        raise ValueError("Policy revision must be positive")
    if (
        type(issued_at_ms) is not int
        or type(expires_at_ms) is not int
        or issued_at_ms < 0
        or not 0 < expires_at_ms - issued_at_ms <= 30 * 24 * 60 * 60 * 1000
    ):
        raise ValueError("Invalid policy validity window")

    envelope = {
        "schema": "shards.operator-policy.v1",
        "revision": revision,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "config": config,
    }
    envelope["signature_hex"] = private_key.sign(canonical_policy_payload(envelope)).hex()
    return envelope


def sign_mtls_ingress_policy(
    config: dict[str, Any],
    private_key: Any,
    *,
    issued_at_ms: int,
    expires_at_ms: int,
    revision: int = 0,
) -> dict[str, Any]:
    """Offline operator signature over exact mTLS ingress identity/bind policy.

    The signing private key must stay in a protected operator environment;
    never give it to a running ingress, MCP relay, agent or kernel.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from shards_kernel.integrations.mtls_ingress import canonical_ingress_policy

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Offline ingress policy requires an Ed25519 signing key")
    if not isinstance(config, dict):
        raise ValueError("Ingress configuration must be a JSON object")
    if (
        type(issued_at_ms) is not int or type(expires_at_ms) is not int
        or issued_at_ms < 0
        or not 0 < expires_at_ms - issued_at_ms <= 24 * 60 * 60 * 1000
    ):
        raise ValueError("Ingress policy validity must not exceed 24 hours")
    if type(revision) is not int or revision < 0:
        raise ValueError("Ingress revision must be a non-negative integer")
    envelope = {
        "schema": "shards.mtls-ingress.v2" if revision else "shards.mtls-ingress.v1",
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "config": config,
    }
    if revision:
        envelope["revision"] = revision
    envelope["signature_hex"] = private_key.sign(
        canonical_ingress_policy(envelope)
    ).hex()
    return envelope
