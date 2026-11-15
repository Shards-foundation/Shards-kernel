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


def _secure_directory_fd(directory: Path) -> int:
    """Open and pin an owner-only directory, rejecting links and path swaps."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _check_pinned_directory(fd, directory)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _check_pinned_directory(fd: int, directory: Path) -> None:
    """Require the named path still identifies the pinned, owner-controlled inode."""
    pinned = os.fstat(fd)
    current = os.stat(directory, follow_symlinks=False)
    if (not stat.S_ISDIR(pinned.st_mode) or pinned.st_uid != os.getuid()
            or pinned.st_mode & 0o077 or not stat.S_ISDIR(current.st_mode)
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)):
        raise ValueError("Approver directory changed or is not owner-only")


def _read_approver_file(directory_fd: int, name: str, limit: int, *,
                        private: bool) -> bytes:
    """Read from the pinned directory; use distinct private/public modes.

    Both file types must be regular, non-symlink, owned by this user and
    size-bounded. Private PEM requires owner-only access; public identities
    may be world-readable (0644), but may not be group/world writable.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        forbidden = 0o077 if private else 0o022
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & forbidden or meta.st_size > limit):
            raise ValueError("Approver key file ownership or permissions invalid")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Approver key file exceeds size limit")
        return data


def ensure_secure_private() -> None:
    """Compatibility validation; real sign flow keeps its directory FD pinned."""
    fd = _secure_directory_fd(DIR)
    try:
        _read_approver_file(fd, PRIVATE.name, 65_536, private=True)
        _read_approver_file(fd, PUBLIC.name, 4_096, private=False)
        try:
            _read_approver_file(fd, PUBLIC_HEX.name, 128, private=False)
        except FileNotFoundError:
            pass
        _check_pinned_directory(fd, DIR)
    finally:
        os.close(fd)


def require_interactive_tty() -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()):
        raise ValueError("Interactive terminal required for human approval")


def get_operator_key(directory_fd: int | None = None) -> Ed25519PrivateKey:
    owns_fd = directory_fd is None
    if directory_fd is None:
        directory_fd = _secure_directory_fd(DIR)
    try:
        _check_pinned_directory(directory_fd, DIR)
        require_interactive_tty()
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Human-approval key passphrase (hidden): ")
        try:
            pem = _read_approver_file(directory_fd, PRIVATE.name, 65_536, private=True)
            key = serialization.load_pem_private_key(pem, password=password.encode())
        finally:
            del password
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Private key must be Ed25519")
        public = serialization.load_pem_public_key(_read_approver_file(directory_fd, PUBLIC.name, 4_096, private=False))
        expected = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if expected != actual:
            raise ValueError("Private and public keys disagree")
        try:
            identity = _read_approver_file(directory_fd, PUBLIC_HEX.name, 128, private=False)
        except FileNotFoundError:
            identity = None
        if identity is not None and identity.decode("ascii").strip() != actual.hex():
            raise ValueError("Hex public identity mismatch")
        _check_pinned_directory(directory_fd, DIR)
        return key
    finally:
        if owns_fd:
            os.close(directory_fd)


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
    """Install an unnamed inode without CAP_DAC_READ_SEARCH.

    The procfs descriptor path refers to this process's open FD, not a
    replaceable file name. Linux linkat(AT_SYMLINK_FOLLOW) follows that
    procfs link to the O_TMPFILE inode, exclusively, without overwriting.
    Fail closed if procfs, O_TMPFILE, or the syscall is unavailable.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_int)
    linkat.restype = ctypes.c_int
    source = f"/proc/self/fd/{fd}".encode("ascii")
    at_fdcwd = getattr(os, "AT_FDCWD", -100)
    at_symlink_follow = getattr(os, "AT_SYMLINK_FOLLOW", 0x400)
    if linkat(at_fdcwd, source, directory_fd, os.fsencode(filename),
              at_symlink_follow) != 0:
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


def write_once(path: Path, data: dict, *, directory_fd: int | None = None) -> None:
    """Safely install a complete approval into a pinned, checked directory.

    Linux O_TMPFILE + descriptor-backed linkat(AT_SYMLINK_FOLLOW). Both the
    anonymous inode and the owner-only output directory remain FD-pinned;
    no pathname-based temporary file or unsafe fallback is permitted.
    """
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    owns_fd = directory_fd is None
    if directory_fd is None:
        directory_fd = _secure_directory_fd(path.parent)
    temp_fd = None
    final_created = False
    try:
        _check_pinned_directory(directory_fd, path.parent)
        temp_fd = os.open(".", os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC,
                          0o600, dir_fd=directory_fd)
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
        # Reconfirm the directory inode and approval validity immediately
        # before publication. Even a later path swap cannot redirect the
        # FD-pinned operation into the replacement directory.
        _check_pinned_directory(directory_fd, path.parent)
        _assert_approval_not_expired(data)
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
        if owns_fd:
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
    # Pin the owner-only directory before key unlock; carry the SAME inode
    # across key reading, revalidation, signing and approval publication.
    directory_fd = _secure_directory_fd(DIR)
    try:
        key = get_operator_key(directory_fd=directory_fd)
        now = int(time.time() * 1000)
        validate_draft(d, now, issuer=args.issuer, key_id=args.key_id, audience=args.audience)
        approval = sign_approval(d, key, now, reviewer=args.reviewer,
                                 issuer=args.issuer, key_id=args.key_id, audience=args.audience)
        output = DIR / f"approval-{d['permit_id'][:16]}.json"
        write_once(output, approval, directory_fd=directory_fd)
    finally:
        os.close(directory_fd)


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
