"""Append-only, hash-chained audit ledger with optional durable storage.

Without a storage adapter, entries remain in process memory. With a storage
adapter, each entry is committed before the in-memory chain advances, and
stored entries are reconstructed and verified before the ledger is usable.
The kernel must treat storage or recovery errors as fatal to execution.
"""

from __future__ import annotations

from typing import Any, Optional

from kernels.common.types import (
    AuditEntry,
    Decision,
    EvidenceBundle,
    KernelState,
)
from kernels.common.errors import AuditError
from kernels.common.hashing import (
    compute_chain_hash,
    compute_hash_dict,
    genesis_hash,
)
from kernels.audit.replay import replay_and_verify
from kernels.common.codec import serialize_for_audit, audit_entry_to_dict


class AuditLedger:
    """Append-only audit ledger with hash-chained entries.

    The ledger enforces append-only semantics. Entries cannot be modified
    or removed once added. The hash chain allows verification of integrity.
    """

    def __init__(self, kernel_id: str, variant: str, storage: Optional[Any] = None) -> None:
        """Initialize an audit ledger, optionally backed by durable storage.

        Args:
            kernel_id: Identifier of the kernel this ledger belongs to.
            variant: Variant name of the kernel.
        """
        self._kernel_id = kernel_id
        self._variant = variant
        self._storage = storage
        self._entries: list[AuditEntry] = []
        self._last_hash = genesis_hash()
        self._next_seq = 0  # Monotonic sequence counter for deterministic ordering
        if self._storage is not None:
            try:
                bind_kernel = getattr(self._storage, "bind_kernel", None)
                if callable(bind_kernel):
                    bind_kernel(self._kernel_id, self._variant)
                self._restore_from_storage()
            except AuditError:
                raise
            except Exception as exc:
                raise AuditError(f"Failed to initialize persistent audit ledger: {exc}") from exc

    def _restore_from_storage(self) -> None:
        """Restore and verify previously committed entries before use.

        Any malformed row or broken chain raises AuditError. Callers must not
        execute tools when persistent audit recovery fails.
        """
        rows = self._storage.list_entries(self._kernel_id)
        if not rows:
            return
        restored: list[AuditEntry] = []
        try:
            for row in rows:
                denial_reasons = row.get("permit_denial_reasons") or ()
                restored.append(
                    AuditEntry(
                        ledger_seq=int(row["ledger_seq"]),
                        prev_hash=str(row["prev_hash"]),
                        entry_hash=str(row["entry_hash"]),
                        ts_ms=int(row["ts_ms"]),
                        request_id=str(row["request_id"]),
                        actor=str(row["actor"]),
                        intent=str(row["intent"]),
                        decision=Decision(row["decision"]),
                        state_from=KernelState(row["state_from"]),
                        state_to=KernelState(row["state_to"]),
                        tool_name=row.get("tool_name"),
                        params_hash=row.get("params_hash"),
                        evidence_hash=row.get("evidence_hash"),
                        error=row.get("error"),
                        permit_digest=row.get("permit_digest"),
                        permit_verification=row.get("permit_verification"),
                        permit_denial_reasons=tuple(denial_reasons),
                        proposal_hash=row.get("proposal_hash"),
                        permit_nonce=row.get("permit_nonce"),
                        permit_issuer=row.get("permit_issuer"),
                        permit_subject=row.get("permit_subject"),
                        permit_max_executions=row.get("permit_max_executions"),
                        audit_phase=row.get("audit_phase"),
                    )
                )
            self.load_verified(tuple(restored), str(rows[-1]["entry_hash"]))
        except AuditError:
            raise
        except Exception as exc:
            raise AuditError(f"Failed to restore persistent audit ledger: {exc}") from exc

    @property
    def kernel_id(self) -> str:
        """Return the kernel ID."""
        return self._kernel_id

    @property
    def variant(self) -> str:
        """Return the kernel variant."""
        return self._variant

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        """Return all entries as an immutable tuple."""
        return tuple(self._entries)

    @property
    def root_hash(self) -> str:
        """Return the current root hash (hash of last entry)."""
        return self._last_hash

    @property
    def length(self) -> int:
        """Return the number of entries in the ledger."""
        return len(self._entries)

    def append(
        self,
        request_id: str,
        actor: str,
        intent: str,
        decision: Decision,
        state_from: KernelState,
        state_to: KernelState,
        ts_ms: int,
        tool_name: Optional[str] = None,
        params: Optional[dict[str, Any]] = None,
        evidence: Optional[str] = None,
        error: Optional[str] = None,
        permit_digest: Optional[str] = None,
        permit_verification: Optional[str] = None,
        permit_denial_reasons: Optional[tuple[str, ...]] = None,
        proposal_hash: Optional[str] = None,
        permit_nonce: Optional[str] = None,
        permit_issuer: Optional[str] = None,
        permit_subject: Optional[str] = None,
        permit_max_executions: Optional[int] = None,
        audit_phase: Optional[str] = None,
    ) -> AuditEntry:
        """Append a new entry to the ledger.

        Args:
            request_id: Unique request identifier.
            actor: Actor who submitted the request.
            intent: Intent of the request.
            decision: Decision made by the kernel.
            state_from: State before transition.
            state_to: State after transition.
            ts_ms: Timestamp in milliseconds.
            tool_name: Name of tool executed, if any.
            params: Parameters passed to tool, if any.
            evidence: Evidence string, if any.
            error: Error message, if any.
            permit_digest: Permit ID if permit was used (v0.2.0+).
            permit_verification: "ALLOW" | "DENY" if permit was verified (v0.2.0+).
            permit_denial_reasons: Reason codes if permit denied (v0.2.0+).
            proposal_hash: Hash of proposal that initiated this request (v0.2.0+).
            permit_nonce: Nonce from permit for ledger-backed replay protection (v0.2.0+).
            permit_issuer: Issuer identity for nonce reconstruction (v0.2.0+).
            permit_subject: Subject identity for nonce reconstruction (v0.2.0+).
            permit_max_executions: Max executions for nonce reconstruction (v0.2.0+).
            audit_phase: "intent" if this records authorisation before a tool
                runs, or "outcome" if it records the result. None for records
                that are not part of a tool execution.

        Returns:
            The newly created audit entry.

        Raises:
            AuditError: If entry creation fails.
        """
        try:
            # Compute hashes for params and evidence
            params_hash = compute_hash_dict(params) if params else None
            evidence_hash = (
                compute_hash_dict({"evidence": evidence}) if evidence else None
            )

            # Serialize entry data for hashing
            entry_data = serialize_for_audit(
                request_id=request_id,
                actor=actor,
                intent=intent,
                decision=decision.value,
                state_from=state_from.value,
                state_to=state_to.value,
                ts_ms=ts_ms,
                tool_name=tool_name,
                params_hash=params_hash,
                evidence_hash=evidence_hash,
                error=error,
                permit_digest=permit_digest,
                permit_verification=permit_verification,
                permit_denial_reasons=permit_denial_reasons,
                proposal_hash=proposal_hash,
                permit_nonce=permit_nonce,
                permit_issuer=permit_issuer,
                permit_subject=permit_subject,
                permit_max_executions=permit_max_executions,
                audit_phase=audit_phase,
            )

            # Compute entry hash using chain
            entry_hash = compute_chain_hash(self._last_hash, entry_data)

            # Assign sequence number
            ledger_seq = self._next_seq

            # Create entry
            entry = AuditEntry(
                ledger_seq=ledger_seq,
                prev_hash=self._last_hash,
                entry_hash=entry_hash,
                ts_ms=ts_ms,
                request_id=request_id,
                actor=actor,
                intent=intent,
                decision=decision,
                state_from=state_from,
                state_to=state_to,
                tool_name=tool_name,
                params_hash=params_hash,
                evidence_hash=evidence_hash,
                error=error,
                permit_digest=permit_digest,
                permit_verification=permit_verification,
                permit_denial_reasons=permit_denial_reasons or tuple(),
                proposal_hash=proposal_hash,
                permit_nonce=permit_nonce,
                permit_issuer=permit_issuer,
                permit_subject=permit_subject,
                permit_max_executions=permit_max_executions,
                audit_phase=audit_phase,
            )

            # Commit to durable storage before mutating the live ledger. If
            # persistence fails, append raises and the caller must fail closed.
            if self._storage is not None:
                self._storage.append(self._kernel_id, audit_entry_to_dict(entry))

            # Append and update chain only after the storage commit succeeds.
            self._entries.append(entry)
            self._last_hash = entry_hash
            self._next_seq += 1  # Increment sequence counter

            return entry

        except Exception as e:
            raise AuditError(f"Failed to append audit entry: {e}") from e

    def load_verified(
        self,
        entries: tuple[AuditEntry, ...] | list[AuditEntry],
        root_hash: str,
    ) -> None:
        """Replace this ledger with entries whose hash chain verifies.

        Nothing is installed if verification fails. A broken chain, a gap in
        ``ledger_seq``, or a root hash that does not match the last entry
        raises AuditError and leaves the current ledger untouched.

        Args:
            entries: Ledger entries, typically from an evidence bundle.
            root_hash: Root hash claimed by the bundle.

        Raises:
            AuditError: If the ledger is already populated or the chain
                does not verify.
        """
        if self._entries:
            raise AuditError("Refusing to load a ledger into a non-empty ledger")

        ordered = tuple(sorted(entries, key=lambda entry: entry.ledger_seq))
        if not ordered:
            if root_hash != genesis_hash():
                raise AuditError("Empty ledger root_hash is not the genesis hash")
            self._last_hash = genesis_hash()
            self._next_seq = 0
            return

        for index, entry in enumerate(ordered):
            if entry.ledger_seq != index:
                raise AuditError(f"Ledger sequence is not contiguous at index {index}")

        payload = [audit_entry_to_dict(entry) for entry in ordered]
        ok, errors = replay_and_verify(payload, expected_root_hash=root_hash)
        if not ok:
            raise AuditError(
                "Audit hash chain verification failed: " + "; ".join(errors)
            )

        self._entries.extend(ordered)
        self._last_hash = ordered[-1].entry_hash
        self._next_seq = ordered[-1].ledger_seq + 1

    def export(self, ts_ms: int) -> EvidenceBundle:
        """Export the ledger as an evidence bundle.

        Args:
            ts_ms: Timestamp of export in milliseconds.

        Returns:
            EvidenceBundle containing all entries and verification data.
        """
        return EvidenceBundle(
            ledger_entries=tuple(self._entries),
            root_hash=self._last_hash,
            exported_at_ms=ts_ms,
            kernel_id=self._kernel_id,
            variant=self._variant,
        )

    def to_list(self) -> list[dict[str, Any]]:
        """Convert ledger to list of dictionaries for serialization.

        Returns:
            List of entry dictionaries.
        """
        return [audit_entry_to_dict(entry) for entry in self._entries]
