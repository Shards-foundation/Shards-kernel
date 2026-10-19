"""Replay verification for audit ledgers.

Provides functions to verify the integrity of an audit ledger by replaying
the hash chain computation and checking for violations.
"""

from dataclasses import dataclass
from typing import Any, Optional

from kernels.common.hashing import compute_chain_hash, genesis_hash
from kernels.common.codec import serialize_for_audit


@dataclass
class ReplayResult:
    """Result of a replay verification."""

    is_valid: bool
    entries_verified: int
    errors: list[str]
    computed_root_hash: str


def replay_and_verify(
    entries: list[dict[str, Any]],
    expected_root_hash: Optional[str] = None,
) -> tuple[bool, list[str]]:
    """Replay and verify an audit ledger.

    Recomputes the hash chain from the entries and verifies that each
    entry's hash matches the computed value.

    Args:
        entries: List of audit entry dictionaries.
        expected_root_hash: Optional expected root hash to verify against.

    Returns:
        Tuple of (is_valid, list of error messages).
    """
    errors: list[str] = []

    if not entries:
        return True, []

    prev_hash = genesis_hash()

    for i, entry in enumerate(entries):
        # Verify prev_hash matches expected
        entry_prev_hash = entry.get("prev_hash", "")
        if entry_prev_hash != prev_hash:
            errors.append(
                f"Entry {i}: prev_hash mismatch. "
                f"Expected {prev_hash[:16]}..., got {entry_prev_hash[:16]}..."
            )

        # Recompute entry hash
        denial_reasons = entry.get("permit_denial_reasons")
        if isinstance(denial_reasons, list):
            denial_reasons = tuple(denial_reasons)
        entry_data = serialize_for_audit(
            request_id=entry.get("request_id", ""),
            actor=entry.get("actor", ""),
            intent=entry.get("intent", ""),
            decision=entry.get("decision", ""),
            state_from=entry.get("state_from", ""),
            state_to=entry.get("state_to", ""),
            ts_ms=entry.get("ts_ms", 0),
            tool_name=entry.get("tool_name"),
            params_hash=entry.get("params_hash"),
            evidence_hash=entry.get("evidence_hash"),
            error=entry.get("error"),
            permit_digest=entry.get("permit_digest"),
            permit_verification=entry.get("permit_verification"),
            permit_denial_reasons=denial_reasons,
            proposal_hash=entry.get("proposal_hash"),
            permit_nonce=entry.get("permit_nonce"),
            permit_issuer=entry.get("permit_issuer"),
            permit_subject=entry.get("permit_subject"),
            permit_max_executions=entry.get("permit_max_executions"),
            audit_phase=entry.get("audit_phase"),
        )

        computed_hash = compute_chain_hash(prev_hash, entry_data)
        entry_hash = entry.get("entry_hash", "")

        if computed_hash != entry_hash:
            errors.append(
                f"Entry {i}: entry_hash mismatch. "
                f"Computed {computed_hash[:16]}..., got {entry_hash[:16]}..."
            )

        # Update prev_hash for next iteration
        prev_hash = entry_hash

    # Verify root hash if provided
    if expected_root_hash is not None and prev_hash != expected_root_hash:
        errors.append(
            f"Root hash mismatch. "
            f"Computed {prev_hash[:16]}..., expected {expected_root_hash[:16]}..."
        )

    return len(errors) == 0, errors


def verify_evidence_bundle(bundle: dict[str, Any]) -> ReplayResult:
    """Verify an evidence bundle.

    Args:
        bundle: Evidence bundle dictionary with ledger_entries and root_hash.

    Returns:
        ReplayResult with verification outcome.
    """
    entries = bundle.get("ledger_entries", [])
    expected_root = bundle.get("root_hash")

    is_valid, errors = replay_and_verify(entries, expected_root)

    # Compute actual root hash
    if entries:
        computed_root = entries[-1].get("entry_hash", genesis_hash())
    else:
        computed_root = genesis_hash()

    return ReplayResult(
        is_valid=is_valid,
        entries_verified=len(entries),
        errors=errors,
        computed_root_hash=computed_root,
    )
