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
    """Signed-config principal metadata; NEVER contains a bearer secret."""

    actor: str
    token_sha256: str
    allowed_tools: frozenset[str]


def identify_agent(
    header: Optional[str], identities: tuple[AgentIdentity, ...]
) -> AgentIdentity | None:
    """Resolve a v2 loopback transport credential to one exact signed identity.

    Token digests are compared in constant time. The raw bearer token is never
    logged, stored in configuration, or used as a kernel signing key.
    """
    if not isinstance(header, str) or not header.startswith("Bearer "):
        return None
    token = header[len("Bearer ") :]
    if (
        not 32 <= len(token) <= 512
        or not token.isascii()
        or any(ch.isspace() for ch in token)
    ):
        return None
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    match: AgentIdentity | None = None
    for identity in identities:
        if hmac.compare_digest(digest, identity.token_sha256):
            match = identity
    return match
