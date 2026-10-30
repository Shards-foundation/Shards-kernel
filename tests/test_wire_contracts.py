"""Tests for JSON wire mapping helpers used by HTTP and MCP adapters."""

import pytest

from shards_kernel import PermitBuilder
from shards_kernel.integrations.wire import (
    boot_strict_kernel,
    evidence_to_mapping,
    permit_from_mapping,
    permit_to_mapping,
    policy_to_mapping,
    receipt_to_mapping,
    request_from_mapping,
    status_mapping,
)


KEYRING = {"k": b"test-secret-key-32-bytes-long123"}


def make_permit():
    return (
        PermitBuilder()
        .issuer("operator")
        .subject("agent")
        .jurisdiction("default")
        .action("echo")
        .params({"message": "hi"})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(100)
        .proposal_hash("proposal")
        .build(KEYRING, "k")
    )


def test_permit_mapping_round_trip_and_missing_fields():
    permit = make_permit()
    payload = permit_to_mapping(permit)
    restored = permit_from_mapping(payload)
    assert restored.permit_id == permit.permit_id
    assert restored.signature == permit.signature
    with pytest.raises(ValueError, match="permit is missing fields"):
        permit_from_mapping({"issuer": "operator"})


def test_request_mapping_normalizes_optional_fields_and_clock():
    kernel = boot_strict_kernel("wire-test")
    request, permit = request_from_mapping(
        kernel,
        {
            "request_id": "r",
            "actor": "agent",
            "intent": "inspect",
            "ts_ms": "invalid",
            "tool_call": {"name": "echo", "params": ["bad"]},
            "params": ["bad"],
            "evidence": ["one", 2],
        },
    )
    assert request.ts_ms == kernel.config.clock.now_ms()
    assert request.params == {}
    assert request.tool_call.params == {}
    assert request.evidence == "one\n2"
    assert permit is None


def test_request_mapping_defaults_params_and_rebuilds_permit():
    kernel = boot_strict_kernel("wire-permit-test")
    payload = {
        "request_id": "r",
        "actor": "agent",
        "intent": "echo",
        "tool_call": {"name": "echo", "params": {"message": "hi"}},
        "permit": permit_to_mapping(make_permit()),
    }
    request, permit = request_from_mapping(kernel, payload)
    assert request.params == {"message": "hi"}
    assert permit is not None
    assert permit.action == "echo"


def test_mapping_helpers_export_status_policy_receipt_and_evidence():
    kernel = boot_strict_kernel("wire-export-test")
    assert status_mapping(kernel) == {"kernel_id": "wire-export-test", "state": "IDLE"}
    policy = policy_to_mapping(kernel)
    assert "allowed_actors" in policy
    request, _ = request_from_mapping(
        kernel, {"request_id": "r", "actor": "unknown", "intent": "inspect"}
    )
    receipt = kernel.submit(request)
    mapped = receipt_to_mapping(receipt)
    assert mapped["request_id"] == "r"
    evidence = evidence_to_mapping(kernel.export_evidence())
    assert evidence["kernel_id"] == "wire-export-test"
    assert evidence["entry_count"] == len(evidence["ledger_entries"])
