#!/usr/bin/env python3
"""Shards isolated human approver — v1.1, review-only pilot.

Local, offline Ed25519 approval documents for EXACT add(7,8) requests.
No network code, no issuer credentials, no auto-approval, no Cloudflare writes.

Based on Shards Kernel 0.1.4 `shards_kernel.cli.offline_issuer.sign_operator_approval`
and the merged Cloudflare issuer pilot `worker.mjs` (PR #146).

This pilot script MUST be independently reviewed before being used to approve
any real Cloudflare signing request. `self-test` uses only ephemeral keys.
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import os
import re
import stat
import warnings
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APPROVAL_DOMAIN = b"SHARDS-OFFLINE-APPROVAL-V1\x00"
DIR = Path.home() / ".local" / "share" / "shards-approver"
PRIVATE = DIR / "approver-private.pem"
PUBLIC = DIR / "approver-public.pem"
PUBLIC_HEX = DIR / "approver-public.hex"
DRAFT_FIELDS = frozenset({
    "permit_id", "issuer", "subject", "jurisdiction", "action", "params",
    "constraints", "max_executions", "valid_from_ms", "valid_until_ms",
    "evidence_hash", "proposal_hash", "nonce", "signature", "key_id",
    "version", "algorithm", "audience",
})
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_32 = re.compile(r"[0-9a-f]{32}\Z")


def canonical(obj: object) -> bytes:
    # No floats, surrogate characters, or nonstandard JSON numbers are allowed.
    def validate(value: object) -> None:
        if value is None or type(value) in (str, int, bool):
            if type(value) is int and not (-(2**53 - 1) <= value <= 2**53 - 1):
                raise ValueError("JSON number exceeds JS safe integer range")
            if type(value) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ValueError("Unpaired UTF-16 surrogate")
            return
        if type(value) is list:
            for item in value:
                validate(item)
            return
        if type(value) is dict:
            for key, val in value.items():
                validate(key)
                validate(val)
            return
        raise ValueError("Unrepresentable JSON value")

    validate(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON member")
        obj[key] = value
    return obj


def valid_identity(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 256 and value == value.strip()
            and "*" not in value and all(ord(x) < 128 for x in value))


def validate_draft_identity(d: dict, *, issuer: str, key_id: str, audience: str) -> None:
    if type(d) is not dict or set(d) != DRAFT_FIELDS:
        raise ValueError("Draft has missing or unknown fields")
    if d["signature"] != "" or d["version"] != 2 or d["algorithm"] != "Ed25519":
        raise ValueError("Only unsigned Ed25519 v2 permit drafts accepted")
    if d["issuer"] != issuer or d["key_id"] != key_id or d["audience"] != audience:
        raise ValueError("Issuer, key-id or audience mismatch")
    if not all(valid_identity(d[n]) for n in ("issuer", "key_id", "subject", "jurisdiction", "audience")):
        raise ValueError("Ambiguous permit identity")


def validate_draft_action(d: dict) -> None:
    if d["action"] != "add" or d["params"] != {"a": 7, "b": 8}:
        raise ValueError("Pilot approver authorises only exact add(7,8)")
    if type(d["params"]["a"]) is not int or type(d["params"]["b"]) is not int:
        raise ValueError("Boolean or non-integer add parameter")
    if (type(d["constraints"]) is not dict or d["constraints"] != {}
            or type(d["max_executions"]) is not int or d["max_executions"] != 1):
        raise ValueError("Constraints or execution count not allowed")


def validate_draft_time(d: dict, now: int) -> None:
    if type(now) is not int or not 0 <= now <= 2**53 - 1:
        raise ValueError("Approval timestamp must be a valid integer")
    if not all(type(d[n]) is int and d[n] >= 0 for n in ("valid_from_ms", "valid_until_ms")):
        raise ValueError("Invalid permit timestamps")
    start, end = d["valid_from_ms"], d["valid_until_ms"]
    if not (0 < end - start <= 900_000 and start <= now < end - 5_000):
        raise ValueError("Permit not currently valid or too close to expiry")


def validate_draft_binding(d: dict) -> None:
    if not (type(d["nonce"]) is str and HEX_32.fullmatch(d["nonce"])):
        raise ValueError("Invalid nonce")
    if not valid_identity(d["proposal_hash"]) or not (
        d["evidence_hash"] == "" or
        (type(d["evidence_hash"]) is str and HEX_64.fullmatch(d["evidence_hash"]))
    ):
        raise ValueError("Invalid evidence/proposal hash")
    if not (type(d["permit_id"]) is str and HEX_64.fullmatch(d["permit_id"])):
        raise ValueError("Malformed permit ID")
    computed = hashlib.sha256(canonical({k: v for k, v in d.items()
                                           if k not in ("permit_id", "signature")})).hexdigest()
    if computed != d["permit_id"]:
        raise ValueError("PERMIT_ID_BINDING_MISMATCH")


def validate_draft(d: dict, now: int, *, issuer: str, key_id: str, audience: str) -> None:
    validate_draft_identity(d, issuer=issuer, key_id=key_id, audience=audience)
    validate_draft_action(d)
    validate_draft_time(d, now)
    validate_draft_binding(d)


def ensure_secure_private() -> None:
    if DIR.is_symlink() or not DIR.is_dir() or DIR.stat().st_uid != os.getuid() or DIR.stat().st_mode & 0o077:
        raise ValueError("Approver directory must be owner-only (mode 700)")
    if PRIVATE.is_symlink() or not PRIVATE.is_file() or PRIVATE.stat().st_mode & 0o077:
        raise ValueError("Approver private key must be a non-symlink owner-only file (mode 600)")
    if PRIVATE.stat().st_uid != os.getuid():
        raise ValueError("Approver private key owner mismatch")
    if PUBLIC.is_symlink() or not PUBLIC.is_file() or PUBLIC_HEX.is_symlink():
        raise ValueError("Public key missing or symlinked")


def require_interactive_tty() -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()):
        raise ValueError("Interactive terminal required for human approval")


def get_operator_key() -> Ed25519PrivateKey:
    ensure_secure_private()
    require_interactive_tty()
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Human-approval key passphrase (hidden): ")
    try:
        key = serialization.load_pem_private_key(PRIVATE.read_bytes(), password=password.encode())
    finally:
        del password
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")
    public = serialization.load_pem_public_key(PUBLIC.read_bytes())
    expected = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if expected != actual:
        raise ValueError("Private and public keys disagree")
    if PUBLIC_HEX.exists() and PUBLIC_HEX.read_text().strip() != actual.hex():
        raise ValueError("Hex public identity mismatch")
    return key


def sign_approval(d: dict, key: Ed25519PrivateKey, now: int, reviewer: str, *,
                  issuer: str, key_id: str, audience: str) -> dict:
    # This helper is public: never rely on approve() to enforce the action policy.
    if type(now) is not int or not 0 <= now <= 2**53 - 1:
        raise ValueError("Approval timestamp must be a valid integer")
    validate_draft(d, now, issuer=issuer, key_id=key_id, audience=audience)
    if not valid_identity(reviewer):
        raise ValueError("Invalid human reviewer identity")
    end = min(now + 60_000, d["valid_until_ms"])
    if end <= now + 5_000:
        raise ValueError("Insufficient approval window")
    approval = {
        "schema": "shards.operator-approval.v1",
        "reviewer": reviewer,
        "permit_sha256": hashlib.sha256(canonical({k: v for k, v in d.items() if k != "signature"})).hexdigest(),
        "permit_id": d["permit_id"],
        "approved_at_ms": now,
        "expires_at_ms": end,
    }
    signed = APPROVAL_DOMAIN + canonical(approval)
    approval["signature_hex"] = key.sign(signed).hex()
    key.public_key().verify(bytes.fromhex(approval["signature_hex"]), signed)
    return approval


def _link_unnamed_file(fd: int, directory_fd: int, filename: str) -> None:
    """Linux linkat(AT_EMPTY_PATH): install the *open inode*, never a pathname.

    Requires O_TMPFILE support. No path-based fallback is permitted because
    a malicious same-user process could replace a named temporary file.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_int)
    linkat.restype = ctypes.c_int
    if linkat(fd, b"", directory_fd, os.fsencode(filename), 0x1000) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), filename)


def _assert_approval_not_expired(data: dict) -> None:
    if data.get("schema") != "shards.operator-approval.v1":
        return
    expiry = data.get("expires_at_ms")
    if type(expiry) is not int or not 0 <= expiry <= 2**53 - 1:
        raise ValueError("Invalid approval expiry")
    if int(time.time() * 1000) >= expiry - 5_000:
        raise ValueError("Approval expired before publication")


def write_once(path: Path, data: dict) -> None:
    """Durably install a complete approval without creating a replaceable temp path.

    Linux-only O_TMPFILE + linkat(AT_EMPTY_PATH), with fail-closed behaviour
    when the filesystem does not support unnamed inodes. Never overwrite.
    """
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temp_fd = None
    final_created = False
    try:
        temp_fd = os.open(path.parent, os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        os.fchmod(temp_fd, 0o600)
        view = memoryview(payload)
        while view:
            count = os.write(temp_fd, view)
            if count <= 0:
                raise OSError("Temporary approval write failed")
            view = view[count:]
        os.fsync(temp_fd)
        metadata = os.fstat(temp_fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600
                or metadata.st_uid != os.getuid() or metadata.st_nlink != 0):
            raise ValueError("Temporary approval inode is not secure")
        _assert_approval_not_expired(data)
        # The unnamed inode is pinned by temp_fd until publication. The kernel
        # enforces no-overwrite semantics with the linkat syscall (EEXIST).
        _link_unnamed_file(temp_fd, directory_fd, path.name)
        final_created = True
        os.fsync(directory_fd)
    except BaseException:
        if final_created:
            os.unlink(path.name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        raise
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        os.close(directory_fd)
    print("Approval document written:", path)
    print("Only this JSON approval document may be transferred; NEVER the private key.")


def load_draft(path_text: str) -> dict:
    # Validate the actual opened inode rather than stat(path) then read(path).
    # O_NONBLOCK prevents being held on a FIFO before fstat can reject it.
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path_text, flags), "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("Draft must be an owner-controlled regular file")
        if metadata.st_mode & 0o022:
            raise ValueError("Draft must not be group or world writable")
        raw = source.read(8193)
    if len(raw) > 8192:
        raise ValueError("Draft JSON exceeds 8192 bytes")
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if type(result) is not dict:
        raise ValueError("Draft must be a JSON object")
    return result


def test() -> None:
    import secrets
    key = Ed25519PrivateKey.generate()  # ephemeral, not stored
    now = int(time.time() * 1000)
    demo = {
        "permit_id": "", "issuer": "pilot-issuer", "subject": "pilot-agent",
        "jurisdiction": "default", "action": "add", "params": {"a": 7, "b": 8},
        "constraints": {}, "max_executions": 1, "valid_from_ms": now - 500,
        "valid_until_ms": now + 120_000, "evidence_hash": "",
        "proposal_hash": "f" * 64, "nonce": secrets.token_hex(16), "signature": "",
        "key_id": "pilot-key", "version": 2, "algorithm": "Ed25519", "audience": "pilot-kernel",
    }
    demo["permit_id"] = hashlib.sha256(canonical({k: v for k, v in demo.items()
                                                 if k not in ("permit_id", "signature")})).hexdigest()
    validate_draft(demo, now, issuer="pilot-issuer", key_id="pilot-key", audience="pilot-kernel")
    approval = sign_approval(demo, key, now, "trusted-human",
                             issuer="pilot-issuer", key_id="pilot-key", audience="pilot-kernel")
    bare = {k: v for k, v in approval.items() if k != "signature_hex"}
    message = APPROVAL_DOMAIN + canonical(bare)
    key.public_key().verify(bytes.fromhex(approval["signature_hex"]), message)
    try:
        invalid = dict(demo, params={"a": 7, "b": 9})
        validate_draft(invalid, now, issuer="pilot-issuer", key_id="pilot-key", audience="pilot-kernel")
    except ValueError:
        pass
    else:
        raise AssertionError("Tampered draft was not denied")
    print("PASS: ephemeral Ed25519 approval canonicalisation, verification and tamper denial")
    print("NO private approver key accessed. NO files written. NO network calls.")


def approve(args) -> None:
    now = int(time.time() * 1000)
    require_interactive_tty()
    d = load_draft(args.draft)
    validate_draft(d, now, issuer=args.issuer, key_id=args.key_id, audience=args.audience)
    digest = hashlib.sha256(canonical({k: v for k, v in d.items() if k != "signature"})).hexdigest()
    print("\nHUMAN APPROVAL — review the actual signed fields:")
    print(json.dumps(d, sort_keys=True, indent=2, ensure_ascii=True))
    print("  canonical draft SHA256:", digest)
    print("  current UTC seconds:", now // 1000)
    challenge = f"APPROVE {d['permit_id']}"
    if input(f"Type EXACTLY '{challenge}' after reviewing: ") != challenge:
        raise ValueError("Human approval not given")
    # Loading the encrypted key can take significant human time. Recheck
    # expiry *after* passphrase entry to avoid emitting stale approvals.
    key = get_operator_key()
    now = int(time.time() * 1000)
    validate_draft(d, now, issuer=args.issuer, key_id=args.key_id, audience=args.audience)
    approval = sign_approval(d, key, now, reviewer=args.reviewer,
                             issuer=args.issuer, key_id=args.key_id, audience=args.audience)
    output = DIR / f"approval-{d['permit_id'][:16]}.json"
    write_once(output, approval)


def main():
    parser = argparse.ArgumentParser(description="Offline Shards human approver — exact add(7,8) only")
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("self-test")
    p = sub.add_parser("approve")
    p.add_argument("draft")
    p.add_argument("--issuer", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--reviewer", required=True)
    args = parser.parse_args()
    if args.mode == "self-test":
        test()
    else:
        approve(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, getpass.GetPassWarning):
        # Avoid printing exception details which might include user-provided JSON.
        print("DENY: Local approval failed (invalid draft, credentials, or environment)", file=sys.stderr)
        sys.exit(2)
