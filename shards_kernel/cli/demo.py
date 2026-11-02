"""Offline, deterministic and intentionally non-production permit walkthrough.

This scenario uses an ephemeral signing key *in the demo process* to show
the public-verifier API, not a deployed or isolated signing authority.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    ToolCall,
    VirtualClock,
)
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey
from shards_kernel.variants.strict_kernel import StrictKernel

_KERNEL_ID = "offline-demonstration-kernel"
_KEY_ID = "ephemeral-demonstration-key"
_ACTOR = "demo-agent"


def _boot_demo_kernel(public_verifier: PublicVerificationKey) -> StrictKernel:
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id=_KERNEL_ID,
            variant="strict",
            clock=VirtualClock(1000),
        )
    )
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({_ACTOR}),
            allowed_tools=frozenset({"echo"}),
        )
    )
    kernel.set_public_verifiers({_KEY_ID: public_verifier})
    return kernel


def _request(request_id: str, text: str = "approved") -> KernelRequest:
    return KernelRequest(
        request_id=request_id,
        ts_ms=1000,
        actor=_ACTOR,
        intent="demonstrate deterministic controlled echo",
        tool_call=ToolCall(name="echo", params={"text": text}),
        params={"text": text},
    )


def _signed_permit(
    private_key: Any, *, valid_until_ms: int = 2000
) -> Any:
    from shards_kernel.issuer import sign_v2_permit

    unsigned = (
        PermitBuilder()
        .issuer("offline-test-operator")
        .subject(_ACTOR)
        .jurisdiction("default")
        .action("echo")
        .params({"text": "approved"})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(valid_until_ms)
        .proposal_hash("demonstration-approval")
        .build_unsigned_v2(key_id=_KEY_ID, audience=_KERNEL_ID)
    )
    return sign_v2_permit(unsigned, private_key)


def run_scenario() -> dict[str, Any]:
    """Execute all local gates; return a verifiable, credential-free report."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    verifier = PublicVerificationKey(
        issuer="offline-test-operator",
        audience=_KERNEL_ID,
        public_key=private_key.public_key().public_bytes_raw(),
    )
    kernel = _boot_demo_kernel(verifier)
    permit = _signed_permit(private_key)
    checks: list[dict[str, Any]] = []

    def record(
        name: str, result: Any, expected: Decision, reason: str = ""
    ) -> None:
        matches = result.decision is expected
        if reason:
            matches = matches and reason in (result.error or "")
        checks.append(
            {
                "id": name,
                "expected": expected.value,
                "observed": result.decision.value,
                "passed": matches,
                "reason_verified": reason if matches and reason else None,
            }
        )

    # Must not invoke echo without a permit.
    record("missing_permit", kernel.submit(_request("denied-without-permit")), Decision.DENY,
           "MISSING_PERMIT")

    approved = kernel.submit(_request("approved-execution"), permit_token=permit)
    record("approved_execution", approved, Decision.ALLOW)
    checks[-1]["passed"] = checks[-1]["passed"] and approved.tool_result == "approved"

    record("same_permit_replay",
           kernel.submit(_request("replayed-execution"), permit_token=permit),
           Decision.DENY, "REPLAY_DETECTED")

    record("scope_change",
           kernel.submit(_request("unapproved-parameters", text="unapproved"),
                         permit_token=permit),
           Decision.DENY, "PARAMS_MISMATCH")

    expired_permit = _signed_permit(private_key, valid_until_ms=999)
    record("expired_permit",
           kernel.submit(_request("expired-execution"), permit_token=expired_permit),
           Decision.DENY, "EXPIRED")

    valid_other_permit = _signed_permit(private_key)
    kernel.set_public_verifiers({_KEY_ID: replace(verifier, revoked=True)})
    record("revoked_signing_key",
           kernel.submit(_request("revoked-execution"), permit_token=valid_other_permit),
           Decision.DENY, "ISSUER_KEY_REVOKED")

    evidence = kernel.export_evidence()
    recovered = _boot_demo_kernel(verifier)
    # Verified ledger hash chain is loaded into a fresh kernel instance; the
    # nonce registry is reconstructed from audited INTENT records.
    recovered.load_ledger(evidence)
    record("ledger_recovered_replay",
           recovered.submit(_request("restored-replay"), permit_token=permit),
           Decision.DENY, "REPLAY_DETECTED")

    return {
        "demo": "OFFLINE_ONLY",
        "production_ready": False,
        "cryptographic_mode": "Ed25519-public-only",
        "evidence_root_hash": evidence.root_hash,
        "audited_entries": len(evidence.ledger_entries),
        "private_key_exposed": False,
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "limitations": [
            "Ephemeral issuer key and verifier run in one test process",
            "Virtual clock, no real-time expiry trust",
            "No external agent identity or TLS ingress",
            "Ledger restored from an in-memory evidence bundle, not durable storage",
            "No transactional cross-replica replay protection",
        ],
    }


def run_demo(*, json_output: bool = False) -> int:
    """Emit result and exit non-zero if any scenario gate is not proven."""
    try:
        report = run_scenario()
    except ImportError:
        report = {
            "demo": "OFFLINE_ONLY",
            "passed": False,
            "error": "Optional crypto dependency missing. Install shards-kernel[crypto].",
        }
    except Exception as exc:
        # Do not print exception strings, which might include secrets.
        report = {
            "demo": "OFFLINE_ONLY",
            "passed": False,
            "error": "Demo failed (" + type(exc).__name__ + ")",
        }

    if json_output:
        print(json.dumps(report, sort_keys=True))
    else:
        print("Shards-Kernel offline evidence demo — NOT a production certification")
        for check in report.get("checks", []):
            print(
                ("PASS" if check["passed"] else "FAIL")
                + ": " + check["id"]
                + " (" + check["observed"] + ")"
            )
        print("Status:", "PASS" if report["passed"] else "FAIL")
        print("Scope: offline, single-process, non-financial, test clock")
        if "error" in report:
            print(report["error"])
    return 0 if report["passed"] else 2
