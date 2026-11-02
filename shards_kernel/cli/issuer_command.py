"""Offline-only issuance CLI: two distinct signing authorities and no key file flags.

The private Ed25519 PEM is supplied through a pre-opened file descriptor
(e.g. an operator secret-manager pipe), not command-line args, environment,
config, HTTP or MCP. The command creates output files with mode 0600 and
refuses overwrites. It never prints private material or permit contents.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from shards_kernel.cli.offline_issuer import (
    issue_approved_permit,
    sign_operator_approval,
    validate_narrow_draft,
)
from shards_kernel.cli.service import _reject_constant, _unique_pairs
from shards_kernel.common.time import SystemClock
from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping

_MAX_INPUT_BYTES = 64 * 1024
_MAX_PEM_BYTES = 8 * 1024


def _load_json_file(path: str) -> Any:
    candidate = Path(path)
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("Input must be an existing non-symlink file")
    if candidate.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("Input too large")
    with candidate.open("rb") as stream:
        data = stream.read(_MAX_INPUT_BYTES + 1)
    if len(data) > _MAX_INPUT_BYTES:
        raise ValueError("Input too large")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON input") from exc


def _reject_float(_raw: str) -> None:
    raise ValueError("Floating point values are not accepted")


def _read_fd_private_key(fd: int) -> Any:
    """Load one short, unencrypted PEM document from an already open FD."""
    if type(fd) is not int or fd < 3:
        raise ValueError("Private key FD must be an operator-provided descriptor >= 3")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with os.fdopen(os.dup(fd), "rb") as stream:
        pem = stream.read(_MAX_PEM_BYTES + 1)
    if not pem or len(pem) > _MAX_PEM_BYTES:
        raise ValueError("Key document is empty or too large")
    try:
        private_key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid Ed25519 private key document") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Only Ed25519 signing keys supported")
    return private_key


def _write_private_output(path: str, data: dict[str, Any]) -> None:
    """Create a new 0600 JSON artifact; never overwrite a previous signature."""
    content = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(content) > _MAX_INPUT_BYTES:
        raise ValueError("Output exceeds configured limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        os.unlink(path)
        raise
    finally:
        os.close(fd)


def run_issuer_command(args: Any) -> int:
    """Do not expose this entrypoint through any model, tool or MCP adapter."""
    try:
        draft = permit_from_mapping(_load_json_file(args.draft))
        validate_narrow_draft(draft)
        signing_key = _read_fd_private_key(args.key_fd)
        now = SystemClock().now_ms()
        if args.issuer_command == "approve":
            approval = sign_operator_approval(
                draft,
                signing_key,
                reviewer=args.reviewer,
                approved_at_ms=now,
                expires_at_ms=now + 5 * 60 * 1000,
            )
            output = approval
        elif args.issuer_command == "sign":
            public_key = args.approver_public_key_hex
            if (
                not isinstance(public_key, str)
                or len(public_key) != 64
                or any(c not in "0123456789abcdef" for c in public_key)
            ):
                raise ValueError("Pinned approval key must be 64 lowercase hex characters")
            approved = _load_json_file(args.approval)
            issued = issue_approved_permit(
                draft,
                approved,
                signing_key,
                bytes.fromhex(public_key),
                now_ms=now,
                expected_issuer=args.expected_issuer,
                expected_key_id=args.expected_key_id,
            )
            output = permit_to_mapping(issued)
        else:
            raise ValueError("Unknown operator issuer action")
        _write_private_output(args.out, output)
    except Exception:
        # No secret bytes, filename, raw exception or parsed approval leave.
        print("Offline issuance refused (invalid input, authority or signature)")
        return 2
    print("Offline issuer artifact created; validate separately before use")
    return 0
