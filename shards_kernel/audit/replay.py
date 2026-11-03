"""Replay verification for audit ledgers.

Provides functions to verify the integrity of an audit ledger by replaying
the hash chain computation and checking for violations.
"""

from dataclasses import dataclass
from typing import Any, Optional

from shards_kernel.common.hashing import compute_chain_hash, genesis_hash
from shards_kernel.common.codec import serialize_for_audit


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

    if not isinstance(entries, list):
        return False, ["ledger_entries must be a list"]
    if expected_root_hash is not None and not isinstance(expected_root_hash, str):
        return False, ["Root hash must be a string"]

    prev_hash = genesis_hash()

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False, errors + [f"Entry {i}: must be a dictionary"]
        required = {
            "prev_hash",
            "entry_hash",
            "ts_ms",
            "request_id",
            "actor",
            "intent",
            "decision",
            "state_from",
            "state_to",
        }
        if not required.issubset(entry):
            return False, errors + [f"Entry {i}: missing required fields"]
        if "ledger_seq" in entry and (
            type(entry["ledger_seq"]) is not int or entry["ledger_seq"] != i
        ):
            errors.append(f"Entry {i}: ledger_seq mismatch")
        # Verify prev_hash matches expected
        entry_prev_hash = entry.get("prev_hash", "")
        if not isinstance(entry_prev_hash, str) or not isinstance(entry.get("entry_hash"), str):
            return False, errors + [f"Entry {i}: hashes must be strings"]
        if entry_prev_hash != prev_hash:
            errors.append(
                f"Entry {i}: prev_hash mismatch. "
                f"Expected {prev_hash[:16]}..., got {entry_prev_hash[:16]}..."
            )

        # Recompute entry hash
        denial_reasons = entry.get("permit_denial_reasons")
        if isinstance(denial_reasons, list):
            denial_reasons = tuple(denial_reasons)
        try:
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
        except (TypeError, ValueError, RecursionError) as exc:
            return False, errors + [f"Entry {i}: malformed data ({exc})"]

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
    if not isinstance(bundle, dict):
        return ReplayResult(False, 0, ["Evidence bundle must be a dictionary"], "")
    if any(field in bundle for field in ("schema", "schema_version")):
        return ReplayResult(False, 0, ["Unknown evidence schema"], "")
    if any(
        not isinstance(key, str) or (key != "ledger_entries" and key.endswith("entries"))
        for key in bundle
    ):
        return ReplayResult(False, 0, ["Unknown evidence entries key"], "")
    entries = bundle.get("ledger_entries")
    expected_root = bundle.get("root_hash")
    if not isinstance(entries, list):
        return ReplayResult(False, 0, ["Missing or invalid ledger_entries"], "")
    if not isinstance(expected_root, str) or not expected_root.strip():
        return ReplayResult(False, 0, ["Missing or invalid root_hash"], "")
    if "entry_count" in bundle and (
        type(bundle["entry_count"]) is not int or bundle["entry_count"] != len(entries)
    ):
        return ReplayResult(False, 0, ["entry_count does not match ledger_entries"], "")

    is_valid, errors = replay_and_verify(entries, expected_root)

    # Only report a root as computed once the complete chain has verified.
    if not is_valid:
        computed_root = ""
    elif entries:
        computed_root = entries[-1].get("entry_hash", genesis_hash())
    else:
        computed_root = genesis_hash()

    return ReplayResult(
        is_valid=is_valid,
        entries_verified=len(entries),
        errors=errors,
        computed_root_hash=computed_root,
    )
