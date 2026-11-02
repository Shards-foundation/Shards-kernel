"""Offline issuer: two independent keys, human approval and exact scope."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import time
from argparse import Namespace
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shards_kernel.cli.issuer_command import run_issuer_command
from shards_kernel.cli.offline_issuer import (
    issue_approved_permit,
    sign_operator_approval,
    validate_narrow_draft,
)
from shards_kernel.common.types import Decision
from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping
from shards_kernel.permits import PermitBuilder, PublicVerificationKey, verify_signature


class OperatorTTY(io.StringIO):
    def isatty(self):
        return True


def draft_for_now(*, minutes=9, tool="echo", max_executions=1):
    now = int(time.time() * 1000)
    permit = (
        PermitBuilder()
        .issuer("offline-issuer")
        .subject("agent-one")
        .jurisdiction("default")
        .action(tool)
        .params({"text": "one-shot"} if tool == "echo" else {"a": 1, "b": 2})
        .max_executions(max_executions)
        .valid_from_ms(now - 5_000)
        .valid_until_ms(now + minutes * 60_000)
        .proposal_hash("reviewed-proposal-hash")
        .build_unsigned_v2(key_id="issuer-key-1", audience="kernel-one")
    )
    return permit, now


def approved_pair(draft, now):
    approver = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    approval = sign_operator_approval(
        draft, approver, reviewer="human-operator",
        approved_at_ms=now, expires_at_ms=now + 5 * 60_000,
    )
    return approver, issuer, approval


def sign(draft, approval, issuer, approver, now):
    return issue_approved_permit(
        draft, approval, issuer, approver.public_key().public_bytes_raw(),
        now_ms=now,
        expected_issuer="offline-issuer",
        expected_key_id="issuer-key-1",
    )


def test_separate_approval_and_issuer_signs_v2_only_and_kernel_verifies_public_only():
    draft, now = draft_for_now()
    approver, issuer, approval = approved_pair(draft, now)
    signed = sign(draft, approval, issuer, approver, now)
    assert signed.version == 2
    assert signed.signature and draft.signature == ""
    assert signed.permit_id == draft.permit_id
    assert verify_signature(
        signed, {}, public_keys={
            "issuer-key-1": PublicVerificationKey(
                issuer="offline-issuer",
                audience="kernel-one",
                public_key=issuer.public_key().public_bytes_raw(),
            )
        }, expected_audience="kernel-one",
    ).status is Decision.ALLOW


def test_no_approval_and_wrong_key_or_issuer_cannot_sign():
    draft, now = draft_for_now()
    approver, issuer, approval = approved_pair(draft, now)
    with pytest.raises(ValueError, match="missing"):
        sign(draft, {}, issuer, approver, now)
    with pytest.raises(ValueError, match="signature"):
        sign(draft, approval, issuer, Ed25519PrivateKey.generate(), now)
    with pytest.raises(ValueError, match="Separation"):
        sign(draft, approval, approver, approver, now)
    with pytest.raises(ValueError, match="issuer"):
        issue_approved_permit(
            draft, approval, issuer, approver.public_key().public_bytes_raw(),
            now_ms=now, expected_issuer="wrong-issuer", expected_key_id="issuer-key-1",
        )
    with pytest.raises(ValueError, match="key ID"):
        issue_approved_permit(
            draft, approval, issuer, approver.public_key().public_bytes_raw(),
            now_ms=now, expected_issuer="offline-issuer", expected_key_id="wrong-key",
        )


@pytest.mark.parametrize("field,value", [
    ("subject", "agent-two"),
    ("audience", "other-kernel"),
    ("action", "add"),
    ("params", {"text": "unapproved"}),
    ("nonce", "a" * 32),
    ("valid_until_ms", "__shorter_validity__"),
    ("key_id", "some-key"),
])
def test_approval_cannot_be_reused_for_modified_draft(field, value):
    draft, now = draft_for_now()
    approver, issuer, approval = approved_pair(draft, now)
    if value == "__shorter_validity__":
        value = now + 30_000  # Still valid, but differs from approved exact scope.
    modified = replace(draft, **{field: value})
    with pytest.raises(ValueError):
        sign(modified, approval, issuer, approver, now)


def test_expired_future_approval_and_tampering_denied():
    draft, now = draft_for_now()
    approver, issuer, approval = approved_pair(draft, now)
    with pytest.raises(ValueError, match="expired"):
        sign(draft, approval, issuer, approver, now + 6 * 60_000)
    with pytest.raises(ValueError, match="expired"):
        sign(draft, approval, issuer, approver, now - 1)
    modified = dict(approval, reviewer="impostor")
    with pytest.raises(ValueError, match="signature"):
        sign(draft, modified, issuer, approver, now)
    modified = dict(approval, signature_hex="00" * 64)
    with pytest.raises(ValueError, match="signature"):
        sign(draft, modified, issuer, approver, now)
    with pytest.raises(ValueError, match="ten minutes"):
        sign_operator_approval(
            draft, approver, reviewer="human-operator",
            approved_at_ms=now, expires_at_ms=now + 11 * 60_000,
        )


def test_invalid_scope_never_enters_offline_signing_flow():
    too_long, _ = draft_for_now(minutes=17)
    with pytest.raises(ValueError, match="15 minutes"):
        validate_narrow_draft(too_long)
    repeated, _ = draft_for_now(max_executions=2)
    with pytest.raises(ValueError, match="single execution"):
        validate_narrow_draft(repeated)
    unknown, _ = draft_for_now(tool="send-wallet-transaction")
    with pytest.raises(ValueError, match="echo/add"):
        validate_narrow_draft(unknown)


def _fd_for_private_key(key):
    read_fd, write_fd = os.pipe()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.write(write_fd, pem)
    os.close(write_fd)
    return read_fd, pem


def test_offline_cli_requires_interactive_review_and_separate_fd_keys(
    tmp_path, monkeypatch, capsys
):
    draft, now = draft_for_now()
    draft_file = tmp_path / "draft.json"
    draft_file.write_text(json.dumps(permit_to_mapping(draft)))
    approval_file = tmp_path / "approval.json"
    signed_file = tmp_path / "permit.json"
    approver = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()

    fd, pem = _fd_for_private_key(approver)
    try:
        args = Namespace(
            issuer_command="approve", draft=str(draft_file), out=str(approval_file),
            reviewer="human-operator", key_fd=fd,
        )
        monkeypatch.setattr(sys, "stdin", io.StringIO("APPROVE " + draft.permit_id + "\n"))
        assert run_issuer_command(args) == 2
        assert not approval_file.exists()
        monkeypatch.setattr(sys, "stdin", OperatorTTY("wrong-id\n"))
        assert run_issuer_command(args) == 2
        assert not approval_file.exists()
        monkeypatch.setattr(sys, "stdin", OperatorTTY("APPROVE " + draft.permit_id + "\n"))
        assert run_issuer_command(args) == 0
    finally:
        os.close(fd)
    approval = json.loads(approval_file.read_text())
    assert approval["permit_id"] == draft.permit_id
    assert stat.S_IMODE(approval_file.stat().st_mode) == 0o600

    fd, issuer_pem = _fd_for_private_key(issuer)
    try:
        args = Namespace(
            issuer_command="sign", draft=str(draft_file), out=str(signed_file),
            key_fd=fd, approval=str(approval_file),
            approver_public_key_hex=approver.public_key().public_bytes_raw().hex(),
            expected_issuer="offline-issuer", expected_key_id="issuer-key-1",
        )
        assert run_issuer_command(args) == 0
        assert run_issuer_command(args) == 2  # O_EXCL: never overwrite
    finally:
        os.close(fd)
    token = permit_from_mapping(json.loads(signed_file.read_text()))
    assert token.signature
    assert token.permit_id == draft.permit_id
    assert stat.S_IMODE(signed_file.stat().st_mode) == 0o600
    output = capsys.readouterr().out
    assert pem.decode("utf-8") not in output
    assert issuer_pem.decode("utf-8") not in output
    assert token.signature not in output
    assert "Offline issuance refused" in output


def test_offline_cli_fails_closed_on_missing_authority_without_file(tmp_path, capsys):
    draft, now = draft_for_now()
    file = tmp_path / "draft.json"
    file.write_text(json.dumps(permit_to_mapping(draft)))
    fd, pem = _fd_for_private_key(Ed25519PrivateKey.generate())
    try:
        args = Namespace(
            issuer_command="sign", draft=str(file), out=str(tmp_path / "signed.json"),
            key_fd=fd, approval=str(tmp_path / "missing.json"),
            approver_public_key_hex="00" * 32,
            expected_issuer="offline-issuer", expected_key_id="issuer-key-1",
        )
        assert run_issuer_command(args) == 2
        assert not (tmp_path / "signed.json").exists()
        assert pem.decode() not in capsys.readouterr().out
    finally:
        os.close(fd)
