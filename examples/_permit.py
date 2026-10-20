"""Shared helper for examples that authorise a tool call."""

from __future__ import annotations

from typing import Any

from kernels.permits import PermitBuilder


def issue_permit(
    keyring: dict[str, bytes],
    key_id: str,
    *,
    subject: str,
    action: str,
    params: dict[str, Any],
    max_executions: int = 1,
    valid_until_ms: int = 10_000_000,
    jurisdiction: str = "default",
    issuer: str = "operator@example.com",
    constraints: dict[str, Any] | None = None,
):
    """Sign a permit for one exact parameter object."""
    return (
        PermitBuilder()
        .issuer(issuer)
        .subject(subject)
        .jurisdiction(jurisdiction)
        .action(action)
        .params(params)
        .constraints({} if constraints is None else constraints)
        .max_executions(max_executions)
        .valid_from_ms(0)
        .valid_until_ms(valid_until_ms)
        .evidence_hash("")
        .proposal_hash(f"proposal-{action}")
        .build(keyring, key_id)
    )
