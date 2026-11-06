"""Clean-wheel SK-001 stress acceptance: 4,000 attempts, no external effects.

Run ONLY from an isolated wheel-installed environment outside the checkout.
Failures are reported as evidence and return nonzero; never rewrite observed
exceptions as passing results. No secrets, network tools or signing keys persist.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import shards_kernel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel import (
    Decision,
    KernelConfig,
    KernelRequest,
    StrictKernel,
    ToolCall,
    VirtualClock,
    replay_and_verify,
)
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey


ACTOR = "wheel-agent"
AUDIENCE = "candidate-wheel-acceptance"
KEY_ID = "ephemeral-test-only"
ATTEMPTS = 1000
WORKERS = 100


def check_installed_wheel() -> str:
    """Reject accidental source-tree import or non-venv execution."""
    package_path = Path(shards_kernel.__file__).resolve()
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    if workspace and package_path.is_relative_to(Path(workspace).resolve()):
        raise RuntimeError("Refusing in-tree package import")
    if "site-packages" not in package_path.parts:
        raise RuntimeError("Candidate must be imported from installed site-packages")
    return str(package_path)


def scenario(limit: int) -> dict[str, object]:
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kernel = StrictKernel()
    kernel.boot(KernelConfig(AUDIENCE, "strict", clock=VirtualClock(1000)))
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({ACTOR}),
            allowed_tools=frozenset({"candidate_sink"}),
        )
    )
    kernel.set_public_verifiers(
        {KEY_ID: PublicVerificationKey("wheel-issuer", AUDIENCE, public_key)}
    )
    executed: list[int] = []
    executed_lock = threading.Lock()

    def candidate_sink(marker: int) -> int:
        with executed_lock:
            executed.append(marker)
        return marker

    kernel._dispatcher.registry.register("candidate_sink", candidate_sink)
    permit = sign_v2_permit(
        (
            PermitBuilder()
            .issuer("wheel-issuer")
            .subject(ACTOR)
            .jurisdiction("default")
            .action("candidate_sink")
            .params({"marker": 7})
            .constraints({})
            .max_executions(limit)
            .valid_from_ms(0)
            .valid_until_ms(2000)
            .proposal_hash("candidate-stress-positive-control")
            .build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE)
        ),
        signing_key,
    )

    def attempt(number: int) -> dict[str, object]:
        request = KernelRequest(
            request_id=f"candidate-{limit}-{number}",
            ts_ms=1000,
            actor=ACTOR,
            intent="Bounded local candidate-wheel sink",
            tool_call=ToolCall("candidate_sink", {"marker": 7}),
            params={"marker": 7},
        )
        try:
            receipt = kernel.submit(request, permit)
            return {
                "decision": receipt.decision.value,
                "error": receipt.error,
            }
        except Exception as exc:
            return {"exception": type(exc).__name__}

    positive = attempt(0)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        rest = list(pool.map(attempt, range(1, ATTEMPTS)))
    outcomes = [positive] + rest
    allowed = sum(x.get("decision") == Decision.ALLOW.value for x in outcomes)
    denied = sum(x.get("decision") == Decision.DENY.value for x in outcomes)
    exceptions = [x for x in outcomes if "exception" in x]
    evidence = kernel.export_evidence()
    verified, audit_errors = replay_and_verify(
        [audit_entry_to_dict(entry) for entry in evidence.ledger_entries],
        evidence.root_hash,
    )
    passed = (
        positive.get("decision") == Decision.ALLOW.value
        and not exceptions
        and allowed + denied == ATTEMPTS
        and 1 <= allowed <= limit
        and len(executed) == allowed
        and set(executed) == {7}
        and verified
    )
    return {
        "limit": limit,
        "attempts": ATTEMPTS,
        "workers": WORKERS,
        "allowed": allowed,
        "denied": denied,
        "effects": len(executed),
        "uncontrolled_exceptions": len(exceptions),
        "exception_samples": exceptions[:3],
        "audit_verified": verified,
        "audit_error_samples": audit_errors[:3],
        "passed": passed,
    }


def main() -> int:
    try:
        module_path = check_installed_wheel()
        rows = [scenario(limit) for limit in (1, 2, 5, 10)]
    except Exception as exc:
        print(json.dumps({"schema": "shards.wheel-sk001.v1", "failure": type(exc).__name__}))
        return 2
    accepted = all(bool(row["passed"]) for row in rows)
    print(
        json.dumps(
            {
                "schema": "shards.wheel-sk001.v1",
                "package_version": shards_kernel.__version__,
                "import_path": module_path,
                "commit_sha": os.environ.get("GITHUB_SHA", "local"),
                "results": rows,
                "accepted": accepted,
            },
            sort_keys=True,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
