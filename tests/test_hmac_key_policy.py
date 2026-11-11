"""Legacy HMAC key policy: empty keys fail closed, short keys are deprecated.

Audit finding (Shards-kernel audit, 11 Nov 2026): the v1 HMAC path accepted an
empty key, so ``PermitBuilder().build({"k": b""}, "k")`` produced a permit
that ``verify_signature`` returned ALLOW for. Anyone who knows the key is empty
can forge such a permit.
"""

from __future__ import annotations

import hashlib
import hmac
import warnings
from dataclasses import replace

import pytest

from shards_kernel.async_support.async_kernel import AsyncKernel
from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)
from shards_kernel.permits import (
    MIN_HMAC_KEY_BYTES,
    STRICT_HMAC_KEYS_ENV,
    PermitBuilder,
    canonical_permit_bytes,
    compute_permit_id,
    sign_permit,
    verify_signature,
)
from shards_kernel.variants.strict_kernel import StrictKernel

GOOD_KEY = b"k" * 32
SHORT_KEY = b"short-key"  # 9 bytes


@pytest.fixture(autouse=True)
def _no_strict_env(monkeypatch):
    monkeypatch.delenv(STRICT_HMAC_KEYS_ENV, raising=False)


def _builder() -> PermitBuilder:
    return (
        PermitBuilder()
        .issuer("operator1")
        .subject("agent1")
        .jurisdiction("default")
        .action("echo")
        .params({"text": "hi"})
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("evidence")
        .proposal_hash("proposal")
    )


def _permit(key: bytes = GOOD_KEY):
    return _builder().build({"k": key}, "k")


def _forged_empty_key_permit():
    """A v1 permit carrying a genuine HMAC-SHA256 signature under ``b""``.

    This is exactly what an attacker could mint when a deployment's key is
    empty, and what the old ``verify_signature`` accepted.
    """
    unsigned = replace(_permit(), signature="")
    canonical = canonical_permit_bytes(
        unsigned, exclude_signature=True, exclude_permit_id=False
    )
    sig = hmac.new(b"", canonical, hashlib.sha256).hexdigest()
    forged = replace(unsigned, signature=sig)
    assert forged.permit_id == compute_permit_id(forged)
    return forged


def _kernel() -> StrictKernel:
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="hmac-key-test", variant="strict", clock=VirtualClock(1000))
    )
    return kernel


# --- Empty keys: always rejected -------------------------------------------


@pytest.mark.parametrize("empty", [b"", bytearray()])
def test_sign_permit_rejects_empty_key(empty):
    with pytest.raises(ValueError, match="must not be empty"):
        sign_permit(replace(_permit(), signature=""), empty, "k")


def test_builder_rejects_empty_key():
    with pytest.raises(ValueError, match="must not be empty"):
        _builder().build({"k": b""}, "k")


def test_set_keyring_rejects_empty_key_and_keeps_existing_keyring():
    kernel = _kernel()
    kernel.set_keyring({"k": GOOD_KEY})
    with pytest.raises(ValueError, match="must not be empty"):
        kernel.set_keyring({"k": GOOD_KEY, "blank": b""})
    assert kernel._keyring == {"k": GOOD_KEY}


def test_async_set_keyring_rejects_empty_key():
    wrapper = AsyncKernel(_kernel())
    with pytest.raises(ValueError, match="must not be empty"):
        wrapper.set_keyring({"k": b""})
    with pytest.raises(ValueError, match="must not be empty"):
        wrapper.set_keyring({"k": b""}, strict_key_length=False)


def test_empty_key_signature_that_used_to_allow_is_now_denied():
    forged = _forged_empty_key_permit()
    result = verify_signature(forged, {"k": b""})
    assert result.status == Decision.DENY
    assert result.reasons == ["HMAC_KEY_EMPTY"]
    # Strict mode off cannot re-enable an empty key either.
    result = verify_signature(forged, {"k": b""}, strict_key_length=False)
    assert result.reasons == ["HMAC_KEY_EMPTY"]


def test_kernel_denies_permit_when_keyring_holds_empty_key():
    """Defence in depth: even a keyring populated without set_keyring fails closed."""
    kernel = _kernel()
    kernel._keyring = {"k": b""}
    forged = _forged_empty_key_permit()
    request = KernelRequest(
        request_id="req-empty-key",
        ts_ms=1000,
        actor="agent1",
        intent="Echo text",
        tool_call=ToolCall(name="echo", params={"text": "hi"}),
        params={"text": "hi"},
    )
    receipt = kernel.submit(request, permit_token=forged)
    assert receipt.status == ReceiptStatus.REJECTED
    assert receipt.decision == Decision.DENY


# --- Short keys: deprecated by default, rejected in strict mode ------------


def test_short_key_warns_but_still_works_by_default():
    with pytest.warns(DeprecationWarning, match="next major version"):
        permit = _permit(SHORT_KEY)
    with pytest.warns(DeprecationWarning, match="shorter than 32 bytes"):
        result = verify_signature(permit, {"k": SHORT_KEY})
    assert result.status == Decision.ALLOW


def test_set_keyring_short_key_warns_and_is_installed():
    kernel = _kernel()
    with pytest.warns(DeprecationWarning, match=STRICT_HMAC_KEYS_ENV):
        kernel.set_keyring({"k": SHORT_KEY})
    assert kernel._keyring == {"k": SHORT_KEY}


def test_strict_argument_rejects_short_key():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_permit(replace(_permit(), signature=""), SHORT_KEY, "k", strict_key_length=True)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _kernel().set_keyring({"k": SHORT_KEY}, strict_key_length=True)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        AsyncKernel(_kernel()).set_keyring({"k": SHORT_KEY}, strict_key_length=True)
    with pytest.warns(DeprecationWarning):
        permit = _permit(SHORT_KEY)
    result = verify_signature(permit, {"k": SHORT_KEY}, strict_key_length=True)
    assert result.status == Decision.DENY
    assert result.reasons == ["HMAC_KEY_TOO_SHORT"]


@pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
def test_strict_environment_rejects_short_key(monkeypatch, value):
    monkeypatch.setenv(STRICT_HMAC_KEYS_ENV, value)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _builder().build({"k": SHORT_KEY}, "k")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _kernel().set_keyring({"k": SHORT_KEY})


def test_explicit_argument_overrides_strict_environment(monkeypatch):
    monkeypatch.setenv(STRICT_HMAC_KEYS_ENV, "1")
    with pytest.warns(DeprecationWarning):
        _kernel().set_keyring({"k": SHORT_KEY}, strict_key_length=False)


@pytest.mark.parametrize("value", ["", "0", "false", "off", "no"])
def test_non_truthy_environment_is_not_strict(monkeypatch, value):
    monkeypatch.setenv(STRICT_HMAC_KEYS_ENV, value)
    with pytest.warns(DeprecationWarning):
        _kernel().set_keyring({"k": SHORT_KEY})


# --- 32+ byte keys: unchanged behaviour ------------------------------------


@pytest.mark.parametrize("key", [GOOD_KEY, b"x" * 64, bytearray(b"y" * 32)])
def test_full_length_key_works_unchanged_without_warning(monkeypatch, key):
    monkeypatch.setenv(STRICT_HMAC_KEYS_ENV, "1")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        permit = _builder().build({"k": key}, "k")
        kernel = _kernel()
        kernel.set_keyring({"k": key})
        result = verify_signature(permit, {"k": key})
    assert result.status == Decision.ALLOW
    expected = hmac.new(
        bytes(key),
        canonical_permit_bytes(permit, exclude_signature=True, exclude_permit_id=False),
        hashlib.sha256,
    ).hexdigest()
    assert permit.signature == expected
    assert MIN_HMAC_KEY_BYTES == 32


def test_non_bytes_key_keeps_previous_type_error():
    """Type errors are still raised by ``hmac`` exactly as before."""
    for key in ("not-bytes", "", memoryview(b"z" * 32)):
        with pytest.raises(TypeError):
            sign_permit(replace(_permit(), signature=""), key, "k")  # type: ignore[arg-type]
