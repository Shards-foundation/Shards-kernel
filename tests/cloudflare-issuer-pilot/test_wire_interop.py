"""Python Shards Kernel 0.1.4 -> JS Worker -> Python verification.

All Ed25519 secrets are generated ephemerally and remain inside CI processes.
No request reaches the deployed Cloudflare Worker. The issuer is still LOCKED.
"""
from __future__ import annotations

import base64
import json
import secrets
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.offline_issuer import sign_operator_approval
from shards_kernel.common.types import Decision
from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping
from shards_kernel.permits import PermitBuilder, PublicVerificationKey, verify_signature


def main() -> None:
    now = int(time.time() * 1000)
    reviewer = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    reviewer_public = reviewer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    issuer_public = issuer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    draft = (
        PermitBuilder()
        .issuer("offline-issuer")
        .subject("qwen-test-agent")
        .jurisdiction("default")
        .action("add")
        .params({"a": 7, "b": 8})
        .valid_from_ms(now - 1000)
        .valid_until_ms(now + 120_000)
        .proposal_hash("f" * 64)
        .build_unsigned_v2(key_id="issuer-key-1", audience="test-kernel")
    )
    approval = sign_operator_approval(
        draft, reviewer, reviewer="trusted-human",
        approved_at_ms=now, expires_at_ms=now + 60_000,
    )
    token = secrets.token_urlsafe(48)
    payload = {
        "approver_public_hex": reviewer_public.hex(),
        "issuer_public_hex": issuer_public.hex(),
        "issuer_private_pkcs8_b64": base64.b64encode(
            issuer.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode("ascii"),
        "issuer": "offline-issuer",
        "key_id": "issuer-key-1",
        "audience": "test-kernel",
        "token": token,
        "draft": permit_to_mapping(draft),
        "approval": approval,
    }

    bridge = Path(__file__).with_name("interop_bridge.mjs")
    run = subprocess.run(
        ["node", str(bridge)],
        input=json.dumps(payload), text=True, capture_output=True,
        timeout=15, check=False,
    )
    if run.returncode != 0:
        # Do NOT emit stderr or stdin: contain ephemeral key material.
        raise AssertionError("Worker bridge exited nonzero")
    result = json.loads(run.stdout)
    assert result["status"] == 200, (
        "Worker refused independently approved Kernel draft", result["status"],
        result["body"].get("code"),
    )
    permit = permit_from_mapping(result["body"]["permit"])
    verifier = {
        "issuer-key-1": PublicVerificationKey(
            issuer="offline-issuer", audience="test-kernel",
            public_key=issuer_public,
        )
    }
    checked = verify_signature(
        permit, {}, public_keys=verifier, expected_audience="test-kernel")
    assert checked.status is Decision.ALLOW, checked.reasons
    wrong = verify_signature(
        permit, {}, public_keys=verifier, expected_audience="wrong-kernel")
    assert wrong.status is Decision.DENY, "Audience override wrongly accepted"
    assert permit.params == {"a": 7, "b": 8}
    assert permit.max_executions == 1
    assert permit.version == 2
    print("PASS: Python Kernel approval -> JS issuer signature -> Python Kernel verification")
    print("PASS: wrong kernel audience denied")


if __name__ == "__main__":
    main()
