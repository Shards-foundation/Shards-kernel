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
