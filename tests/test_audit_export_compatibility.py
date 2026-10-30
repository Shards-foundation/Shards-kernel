"""Serialization contract tests for audit export compatibility."""

from types import SimpleNamespace

from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.types import Decision, KernelState


def test_audit_export_normalizes_enum_values_and_preserves_permit_metadata():
    entry = SimpleNamespace(
        ledger_seq=4,
        prev_hash="previous",
        entry_hash="current",
        ts_ms=42,
        request_id="request",
        actor="operator",
        intent="inspect",
        decision=Decision.ALLOW,
        state_from=KernelState.IDLE,
        state_to=KernelState.COMPLETED,
        tool_name="inspect",
        params_hash="params",
        evidence_hash="evidence",
        error=None,
        permit_digest="digest",
        permit_verification="ALLOW",
        permit_denial_reasons=("REPLAY", "EXPIRED"),
        proposal_hash="proposal",
        permit_nonce="nonce",
        permit_issuer="issuer",
        permit_subject="subject",
        permit_max_executions=3,
        audit_phase="outcome",
    )
    result = audit_entry_to_dict(entry)
    assert result["ledger_seq"] == 4
    assert result["decision"] == "ALLOW"
    assert result["state_from"] == "IDLE"
    assert result["state_to"] == "COMPLETED"
    assert result["permit_denial_reasons"] == ["REPLAY", "EXPIRED"]
    assert result["permit_nonce"] == "nonce"
    assert result["permit_max_executions"] == 3
    assert result["audit_phase"] == "outcome"


def test_audit_export_supports_older_entries_without_permit_fields():
    entry = SimpleNamespace(
        prev_hash="p",
        entry_hash="e",
        ts_ms=0,
        request_id="r",
        actor="a",
        intent="i",
        decision="DENY",
        state_from="IDLE",
        state_to="HALTED",
        tool_name=None,
        params_hash=None,
        evidence_hash=None,
        error="blocked",
    )
    result = audit_entry_to_dict(entry)
    assert result["ledger_seq"] == 0
    assert result["decision"] == "DENY"
    assert result["state_from"] == "IDLE"
    assert "permit_digest" not in result
    assert result["audit_phase"] is None
