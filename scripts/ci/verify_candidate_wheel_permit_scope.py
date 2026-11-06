"""Installed-wheel security acceptance for exact signed execution parameters.

Run outside the source checkout using a newly built candidate wheel installed in
a clean virtual environment. Uses ephemeral local Ed25519 keys and deterministic
in-memory handlers; no external side effects, credentials, or network calls.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel import (
    Decision,
    KernelConfig,
    KernelRequest,
    StrictKernel,
    ToolCall,
    VirtualClock,
    __file__ as package_init_path,
    __version__,
    replay_and_verify,
)
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey


CASES: tuple[tuple[str, str, dict[str, Any], dict[str, Any], bool], ...] = (
    ("exact", "kwargs", {"marker": "approved"}, {"marker": "approved"}, True),
    ("empty_exact", "kwargs", {}, {}, True),
    (
        "omit_signed_field",
        "kwargs",
        {"marker": "approved", "unused": "signed"},
        {"marker": "approved"},
        False,
    ),
    ("omit_signed_null", "kwargs", {"marker": None}, {}, False),
    ("bool_int_alias", "kwargs", {"marker": 1}, {"marker": True}, False),
    (
        "add_unsigned_field",
        "kwargs",
        {"marker": "approved"},
        {"marker": "approved", "unexpected": 1},
        False,
    ),
    (
        "nested_json_alias",
        "kwargs",
        {"nested": [1, {"trusted": True}]},
        {"nested": [1, {"trusted": 1}]},
        False,
    ),
    ("signed_resolved_default", "default", {"marker": 99}, {}, True),
    ("unauthorised_default", "default", {"marker": 7}, {}, False),
)


def ensure_clean_wheel() -> str:
    path = Path(package_init_path).resolve()
    if "site-packages" not in path.parts:
        raise RuntimeError("Wheel security probe requires installed site-packages")
    checkout = os.environ.get("GITHUB_WORKSPACE")
    if checkout and path.is_relative_to(Path(checkout).resolve()):
        raise RuntimeError("In-tree imports are forbidden in wheel security acceptance")
    return str(path)


def evaluate_case(
    name: str,
    handler_type: str,
    signed: dict[str, Any],
    submitted: dict[str, Any],
    expect_allow: bool,
) -> dict[str, Any]:
    audience = "sk002-wheel-" + name
    issuer = "acceptance-signer"
    actor = "local-probe"
    action = "candidate_probe"
    key_id = "ephemeral-sk002-key"
    signing_key = Ed25519PrivateKey.generate()
    verifier_bytes = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kernel = StrictKernel()
    kernel.boot(KernelConfig(audience, "strict", clock=VirtualClock(1000)))
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({actor}),
            allowed_tools=frozenset({action}),
        )
    )
    kernel.set_public_verifiers(
        {key_id: PublicVerificationKey(issuer, audience, verifier_bytes)}
    )

    executed: list[dict[str, Any]] = []

    if handler_type == "default":
        def handler(marker: int = 99) -> int:
            executed.append({"marker": marker})
            return marker
    else:
        def handler(**kwargs: Any) -> dict[str, Any]:
            executed.append(kwargs)
            return kwargs

    kernel._dispatcher.registry.register(action, handler)
    unsigned = (
        PermitBuilder()
        .issuer(issuer)
        .subject(actor)
        .jurisdiction("default")
        .action(action)
        .params(signed)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(2000)
        .proposal_hash("sk002-acceptance-" + name)
        .build_unsigned_v2(key_id=key_id, audience=audience)
    )
    permit = sign_v2_permit(unsigned, signing_key)
    request = KernelRequest(
        request_id="sk002-" + name,
        ts_ms=1000,
        actor=actor,
        intent="local signed-scope candidate-wheel acceptance",
        tool_call=ToolCall(action, submitted),
        params=submitted,
    )
    try:
        receipt = kernel.submit(request, permit)
        decision = receipt.decision
        failure = None
        error = receipt.error
    except Exception as exc:
        decision = None
        failure = type(exc).__name__
        error = None

    evidence = kernel.export_evidence()
    verified, verification_errors = replay_and_verify(
        [audit_entry_to_dict(e) for e in evidence.ledger_entries],
        evidence.root_hash,
    )
    wanted = Decision.ALLOW if expect_allow else Decision.DENY
    expected_effects = (
        [{"marker": 99}] if expect_allow and handler_type == "default"
        else [submitted] if expect_allow
        else []
    )
    passed = (
        failure is None
        and decision is wanted
        and executed == expected_effects
        and verified
        and bool(evidence.ledger_entries)
        and (
            expect_allow
            or (
                error is not None
                and (
                    "PARAMS_MISMATCH" in error
                    or "PARAM_BINDING_MISMATCH" in error
                )
            )
        )
    )
    return {
        "name": name,
        "expected": wanted.value,
        "decision": decision.value if decision is not None else None,
        "effect_count": len(executed),
        "uncontrolled_exception": failure,
        "audit_verified": verified,
        "audit_errors": verification_errors[:2],
        "accepted": passed,
    }


def main() -> int:
    try:
        import_path = ensure_clean_wheel()
        results = [evaluate_case(*case) for case in CASES]
    except Exception as exc:
        print(json.dumps({"schema": "shards.wheel-sk002.v1", "failure": type(exc).__name__}))
        return 2

    accepted = len(results) == len(CASES) and all(
        bool(case["accepted"]) for case in results
    )
    print(json.dumps({
        "schema": "shards.wheel-sk002.v1",
        "package_version": __version__,
        "python_version": sys.version.split()[0],
        "wheel_import_path": import_path,
        "cases": results,
        "accepted": accepted,
    }, sort_keys=True))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
