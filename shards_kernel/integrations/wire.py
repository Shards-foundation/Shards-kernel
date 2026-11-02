"""Translate HTTP and MCP payloads into kernel requests.

The caller sends one parameter object. It is copied onto both
``request.params`` and the tool call, which is the binding the kernel
authorises. An explicit ``params`` field that differs from the tool call
is left as sent, and the kernel rejects it.
"""

from __future__ import annotations

from typing import Any, Optional

from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.types import (
    EvidenceBundle,
    KernelConfig,
    KernelReceipt,
    KernelRequest,
    ToolCall,
    VirtualClock,
)
from shards_kernel.common.time import SystemClock
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitToken
from shards_kernel.variants.base import BaseKernel
from shards_kernel.variants.strict_kernel import StrictKernel

_PERMIT_FIELDS = (
    "permit_id",
    "issuer",
    "subject",
    "jurisdiction",
    "action",
    "params",
    "constraints",
    "max_executions",
    "valid_from_ms",
    "valid_until_ms",
    "evidence_hash",
    "proposal_hash",
    "nonce",
    "signature",
    "key_id",
)


def boot_strict_kernel(kernel_id: str) -> StrictKernel:
    """Boot a strict kernel with a virtual clock. The caller sets the keyring."""
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id=kernel_id,
            variant="strict",
            clock=VirtualClock(0),
        )
    )
    return kernel


def boot_service_kernel(kernel_id: str) -> StrictKernel:
    """Boot a real-time service kernel with an explicit deny-all policy.

    Keyring and a scoped jurisdiction policy must be configured by the
    trusted operator before any tool can execute. Never use VirtualClock for
    service permit expiry checks.
    """
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id=kernel_id,
            variant="strict",
            clock=SystemClock(),
        )
    )
    kernel.set_policy(JurisdictionPolicy.strict())
    return kernel


def permit_to_mapping(permit: PermitToken) -> dict[str, Any]:
    """Serialise a permit for an HTTP body."""
    result = {name: getattr(permit, name) for name in _PERMIT_FIELDS}
    if permit.version == 2:
        result.update(
            version=permit.version, algorithm=permit.algorithm, audience=permit.audience
        )
    return result


def permit_from_mapping(data: dict[str, Any]) -> PermitToken:
    """Rebuild a permit. Verification still happens inside the kernel."""
    missing = [name for name in _PERMIT_FIELDS if name not in data]
    if missing:
        raise ValueError("permit is missing fields: " + ", ".join(missing))
    values = {name: data[name] for name in _PERMIT_FIELDS}
    if data.get("version", 1) == 2:
        if not all(field in data for field in ("algorithm", "audience")):
            raise ValueError("v2 permit missing algorithm or audience")
        values.update(
            version=data["version"],
            algorithm=data["algorithm"],
            audience=data["audience"],
        )
    elif any(field in data for field in ("version", "algorithm", "audience")):
        # Legacy v1 is accepted ONLY without conflicting v2 claims.
        if data.get("version", 1) != 1 or data.get("algorithm", "HS256") != "HS256" or data.get("audience", ""):
            raise ValueError("Invalid legacy permit version, algorithm or audience")
    denial_reasons = values.get("constraints")
    if denial_reasons is None:
        values["constraints"] = {}
    if values.get("params") is None:
        values["params"] = {}
    return PermitToken(**values)


def request_from_mapping(
    kernel: BaseKernel, data: dict[str, Any]
) -> tuple[KernelRequest, Optional[PermitToken]]:
    """Build a request and an optional permit from an HTTP or MCP body."""
    tool_payload = data.get("tool_call")
    tool_call = None
    tool_params: dict[str, Any] = {}
    if tool_payload:
        raw_params = tool_payload.get("params") or {}
        if not isinstance(raw_params, dict):
            raw_params = {}
        tool_params = dict(raw_params)
        tool_call = ToolCall(name=tool_payload.get("name") or "", params=tool_params)

    if "params" in data and data["params"] is not None:
        params = data["params"] if isinstance(data["params"], dict) else {}
    else:
        params = dict(tool_params)

    evidence = data.get("evidence")
    if isinstance(evidence, list):
        evidence = "\n".join(str(item) for item in evidence) or None
    if evidence is not None and not isinstance(evidence, str):
        evidence = str(evidence)

    ts_ms = data.get("ts_ms")
    if not isinstance(ts_ms, int):
        ts_ms = kernel.config.clock.now_ms()

    request = KernelRequest(
        request_id=str(data["request_id"]),
        ts_ms=ts_ms,
        actor=str(data["actor"]),
        intent=str(data.get("intent") or ""),
        tool_call=tool_call,
        params=params,
        evidence=evidence,
    )
    permit = None
    if data.get("permit"):
        permit = permit_from_mapping(data["permit"])
    return request, permit


def receipt_to_mapping(receipt: KernelReceipt) -> dict[str, Any]:
    """JSON-ready receipt. ``result`` is the tool value that ran."""
    return {
        "request_id": receipt.request_id,
        "status": receipt.status.value,
        "decision": receipt.decision.value,
        "state_from": receipt.state_from.value,
        "state_to": receipt.state_to.value,
        "ts_ms": receipt.ts_ms,
        "result": receipt.tool_result,
        "error": receipt.error,
        "evidence_hash": receipt.evidence_hash,
    }


def evidence_to_mapping(bundle: EvidenceBundle) -> dict[str, Any]:
    """JSON-ready evidence bundle."""
    return {
        "kernel_id": bundle.kernel_id,
        "variant": bundle.variant,
        "exported_at_ms": bundle.exported_at_ms,
        "root_hash": bundle.root_hash,
        "entry_count": len(bundle.ledger_entries),
        "ledger_entries": [audit_entry_to_dict(entry) for entry in bundle.ledger_entries],
    }


def policy_to_mapping(kernel: BaseKernel) -> dict[str, Any]:
    """JSON-ready policy summary."""
    policy = kernel.policy
    return {
        "allowed_actors": sorted(policy.allowed_actors),
        "allowed_tools": sorted(policy.allowed_tools),
        "allow_intent_only": policy.allow_intent_only,
        "max_intent_length": policy.max_intent_length,
    }


def status_mapping(kernel: BaseKernel) -> dict[str, Any]:
    """JSON-ready status."""
    return {
        "kernel_id": kernel.config.kernel_id,
        "state": kernel.get_state().value,
    }
