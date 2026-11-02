"""Shared bearer-token authentication for HTTP integration adapters.

A transport credential authenticates callers to the HTTP interface; it does not
replace execution permits, actor authorisation, or policy evaluation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Optional


def resolve_api_key(api_key: Optional[str] = None) -> str:
    """Require an explicitly configured HTTP credential before serving requests."""
    key = api_key if api_key is not None else os.environ.get("SHARDS_KERNEL_API_KEY")
    if not isinstance(key, str) or len(key) < 32 or key != key.strip():
        raise ValueError(
            "HTTP API key must contain at least 32 characters; "
            "pass api_key or set SHARDS_KERNEL_API_KEY"
        )
    return key


def bearer_authorized(header: Optional[str], api_key: str) -> bool:
    """Compare a bearer credential without normalising or logging its contents."""
    if not isinstance(header, str) or not header.startswith("Bearer "):
        return False
    supplied = header[len("Bearer ") :]
    return hmac.compare_digest(supplied, api_key)


@dataclass(frozen=True)
class AgentIdentity:
    """Public identity and memory-hard token verifier, not a bearer secret."""

    actor: str
    token_scrypt: str
    allowed_tools: frozenset[str]


def resolve_agent_pepper(pepper: str | None = None) -> bytes:
    """Require a separately provisioned secret for per-agent KDF salts."""
    value = pepper if pepper is not None else os.environ.get("SHARDS_KERNEL_AGENT_AUTH_PEPPER")
    if not isinstance(value, str) or not 32 <= len(value) <= 512 or value != value.strip():
        raise ValueError("Operator must provision a separate 32+ character agent authentication pepper")
    return value.encode("utf-8")


def agent_token_kdf(token: str, pepper: bytes) -> str:
    """Derive a per-actor, memory-hard verifier for an agent-labelled token.

    An operator provisions `<actor>.<cryptographically-random-secret>`.
    The actor prefix is public routing metadata, NEVER an identity proof.
    """
    if not isinstance(token, str) or not token.isascii() or token.count(".") != 1:
        raise ValueError("Token must be actor-labelled and ASCII")
    actor, secret = token.split(".", 1)
    if (
        not actor or not 32 <= len(secret) <= 512
        or any(c.isspace() for c in secret)
    ):
        raise ValueError("Token must include a nonempty actor and high-entropy secret")
    # scrypt is itself a memory-hard KDF: use a domain-separated,
    # actor-specific secret salt without a preliminary fast password hash.
    salt = (
        b"SHARDS-AGENT-TOKEN-SCRYPT-V2\x00"
        + len(pepper).to_bytes(2, "big")
        + pepper
        + actor.encode("ascii")
    )
    return hashlib.scrypt(
        token.encode("ascii"), salt=salt, n=2**14, r=8, p=1, dklen=32
    ).hex()


def identify_agent(
    header: Optional[str], identities: tuple[AgentIdentity, ...], pepper: bytes
) -> AgentIdentity | None:
    """Bind an agent-labelled bearer to one pinned principal using scrypt.

    The untrusted label selects the verifier row only. It cannot authenticate
    the actor without the constant-time memory-hard digest comparison.
    """
    if not isinstance(header, str) or not header.startswith("Bearer "):
        return None
    token = header[len("Bearer ") :]
    if (
        len(token) > 640 or not token.isascii()
        or any(ch.isspace() for ch in token) or token.count(".") != 1
    ):
        return None
    actor = token.split(".", 1)[0]
    for identity in identities:
        if identity.actor == actor:
            try:
                derived = agent_token_kdf(token, pepper)
            except (ValueError, UnicodeError):
                return None
            return identity if hmac.compare_digest(derived, identity.token_scrypt) else None
    return None
