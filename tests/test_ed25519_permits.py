"""Adversarial v2 Ed25519 tests: verifier only holds operator public keys."""

from dataclasses import replace

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.common.types import Decision, KernelConfig, KernelRequest, ToolCall, VirtualClock
from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder, PublicVerificationKey, verify_signature
from shards_kernel.variants.strict_kernel import StrictKernel


KEY_ID = "operator-ed25519-1"
AUDIENCE = "audience-kernel-test"


def setup():
    signing_key = Ed25519PrivateKey.generate()
    public_bytes = signing_key.public_key().public_bytes_raw()
    verifier = PublicVerificationKey(issuer="operator", audience=AUDIENCE, public_key=public_bytes)
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000))
    )
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}), allowed_tools=frozenset({"echo"})
        )
    )
    kernel.set_public_verifiers({KEY_ID: verifier})
    return kernel, signing_key, verifier


def make_permit(key, *, audience=AUDIENCE, issuer="operator", from_ms=0, until_ms=2000):
    unsigned = (
        PermitBuilder()
        .issuer(issuer)
        .subject("alice")
        .jurisdiction("default")
        .action("echo")
        .params({"text": "hello"})
        .constraints({})
        .max_executions(1)
        .valid_from_ms(from_ms)
        .valid_until_ms(until_ms)
        .proposal_hash("approved-proposal")
        .build_unsigned_v2(key_id=KEY_ID, audience=audience)
    )
    return sign_v2_permit(unsigned, key)


def request(request_id):
    return KernelRequest(
        request_id=request_id,
        ts_ms=1000,
        actor="alice",
        intent="echo approved text",
        tool_call=ToolCall(name="echo", params={"text": "hello"}),
        params={"text": "hello"},
    )


def test_only_public_key_needed_for_valid_execution_and_replay_prevention():
    kernel, private_key, _verifier = setup()
    permit = make_permit(private_key)
    assert kernel._keyring == {}
    assert all(isinstance(record.public_key, bytes) and len(record.public_key) == 32
               for record in kernel._public_verifiers.values())
    mapped = permit_to_mapping(permit)
    restored = permit_from_mapping(mapped)
    assert restored == permit
    first = kernel.submit(request("first"), permit_token=restored)
    assert first.decision is Decision.ALLOW
    assert first.tool_result == "hello"
    duplicate = kernel.submit(request("again"), permit_token=restored)
    assert duplicate.decision is Decision.DENY
    assert "REPLAY_DETECTED" in (duplicate.error or "")
    assert kernel.export_evidence().ledger_entries


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("issuer", "wrong-issuer", "ISSUER_MISMATCH"),
        ("audience", "wrong-kernel", "AUDIENCE_MISMATCH"),
        ("params", {"text": "tampered"}, "PERMIT_ID_MISMATCH"),
        ("signature", "00" * 64, "SIGNATURE_INVALID"),
        ("version", 1, "ValueError"),
        ("algorithm", "HS256", "ValueError"),
    ],
)
def test_verifier_fails_closed_on_tampering(field, value, reason):
    kernel, private_key, _verifier = setup()
    permit = make_permit(private_key)
    if reason == "ValueError":
        with pytest.raises(ValueError):
            replace(permit, **{field: value})
        return
    changed = replace(permit, **{field: value})
    outcome = kernel.submit(request("tampered-" + field), permit_token=changed)
    assert outcome.decision is Decision.DENY
    assert reason in (outcome.error or "")
    assert outcome.tool_result is None


def test_public_mode_blocks_legacy_hmac_algorithm_confusion():
    kernel, private_key, _ = setup()
    with pytest.raises(ValueError, match="Public-only"):
        kernel.set_keyring({"legacy": b"a" * 32})

    from shards_kernel.permits import verify_permit, NonceRegistry
    legacy = (
        PermitBuilder()
        .issuer("operator")
        .subject("alice")
        .jurisdiction("default")
        .action("echo")
        .params({"text": "hello"})
        .valid_from_ms(0)
        .valid_until_ms(2000)
        .proposal_hash("legacy")
        .build({"legacy": b"a" * 32}, "legacy")
    )
    result = verify_permit(
        legacy, {}, NonceRegistry(), 1000, "default", frozenset({"echo"}),
        "alice", {"text": "hello"}, public_keys=kernel._public_verifiers,
        expected_audience=AUDIENCE,
    )
    assert "ALGORITHM_NOT_ALLOWED" in result.reasons

    other = StrictKernel()
    other.boot(KernelConfig(kernel_id=AUDIENCE, variant="strict", clock=VirtualClock(1000)))
    other.set_keyring({"legacy": b"a" * 32})
    with pytest.raises(ValueError, match="HMAC secrets"):
        other.set_public_verifiers(kernel._public_verifiers)
    v2 = make_permit(private_key)
    assert "ALGORITHM_NOT_ALLOWED" in verify_signature(v2, {"legacy": b"a" * 32}).reasons


def test_key_revocation_rotation_and_wrong_public_key():
    kernel, private_key, verifier = setup()
    permit = make_permit(private_key)
    kernel.set_public_verifiers({KEY_ID: replace(verifier, revoked=True)})
    refused = kernel.submit(request("revoked"), permit_token=permit)
    assert refused.decision is Decision.DENY
    assert "ISSUER_KEY_REVOKED" in (refused.error or "")
    kernel.set_public_verifiers({})
    unknown = kernel.submit(request("unknown"), permit_token=permit)
    assert "UNKNOWN_KEY_ID" in (unknown.error or "")

    attacker = Ed25519PrivateKey.generate()
    kernel.set_public_verifiers({
        KEY_ID: replace(verifier, public_key=attacker.public_key().public_bytes_raw())
    })
    forged = kernel.submit(request("wrong-key"), permit_token=permit)
    assert "SIGNATURE_INVALID" in (forged.error or "")


def test_valid_signature_rejected_by_wrong_intended_kernel_and_expiry():
    kernel, private_key, verifier = setup()
    wrong_audience_permit = make_permit(private_key, audience="some-other-kernel")
    outcome = kernel.submit(request("wrong-audience"), permit_token=wrong_audience_permit)
    assert "AUDIENCE_MISMATCH" in (outcome.error or "")

    expired = make_permit(private_key, until_ms=999)
    result = kernel.submit(request("expired"), permit_token=expired)
    assert "EXPIRED" in (result.error or "")
    assert result.tool_result is None

    premature = make_permit(private_key, from_ms=1001)
    result = kernel.submit(request("future"), permit_token=premature)
    assert "NOT_YET_VALID" in (result.error or "")


def test_public_key_metadata_is_validated_and_unsigned_input_cannot_be_signed_twice():
    _, private_key, verifier = setup()
    with pytest.raises(ValueError, match="32 raw bytes"):
        PublicVerificationKey("operator", AUDIENCE, b"too-short")
    with pytest.raises(ValueError, match="required"):
        PublicVerificationKey("", AUDIENCE, verifier.public_key)

    permit = make_permit(private_key)
    with pytest.raises(ValueError, match="already has a signature"):
        sign_v2_permit(permit, private_key)
    with pytest.raises(TypeError):
        sign_v2_permit(replace(permit, signature=""), object())

    mapped = permit_to_mapping(permit)
    for key in ("algorithm", "audience"):
        bad = dict(mapped)
        bad.pop(key)
        with pytest.raises(ValueError):
            permit_from_mapping(bad)
