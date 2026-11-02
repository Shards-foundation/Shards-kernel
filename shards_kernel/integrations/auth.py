"""Shared bearer-token authentication for HTTP integration adapters.

A transport credential authenticates callers to the HTTP interface; it does not
replace execution permits, actor authorisation, or policy evaluation.
"""

from __future__ import annotations

import hmac
import os
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
