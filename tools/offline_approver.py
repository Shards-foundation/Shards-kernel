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
import getpass
import hashlib
import json
import os
import re
import stat
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


def validate_draft(d: dict, now: int, *, issuer: str, key_id: str, audience: str) -> None:
    if type(d) is not dict or set(d) != DRAFT_FIELDS:
        raise ValueError("Draft has missing or unknown fields")
    if d["signature"] != "" or d["version"] != 2 or d["algorithm"] != "Ed25519":
        raise ValueError("Only unsigned Ed25519 v2 permit drafts accepted")
    if d["issuer"] != issuer or d["key_id"] != key_id or d["audience"] != audience:
        raise ValueError("Issuer, key-id or audience mismatch")
    if not all(valid_identity(d[n]) for n in ("issuer", "key_id", "subject", "jurisdiction", "audience")):
        raise ValueError("Ambiguous permit identity")
    if d["action"] != "add" or d["params"] != {"a": 7, "b": 8}:
        raise ValueError("Pilot approver authorises only exact add(7,8)")
    if type(d["params"]["a"]) is not int or type(d["params"]["b"]) is not int:
        raise ValueError("Boolean or non-integer add parameter")
    if type(d["constraints"]) is not dict or d["constraints"] != {} or type(d["max_executions"]) is not int or d["max_executions"] != 1:
        raise ValueError("Constraints or execution count not allowed")
    if not all(type(d[n]) is int and d[n] >= 0 for n in ("valid_from_ms", "valid_until_ms")):
        raise ValueError("Invalid permit timestamps")
    start, end = d["valid_from_ms"], d["valid_until_ms"]
    if not (0 < end - start <= 900_000 and start <= now < end - 5_000):
        raise ValueError("Permit not currently valid or too close to expiry")
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


def ensure_secure_private() -> None:
    if DIR.is_symlink() or not DIR.is_dir() or DIR.stat().st_uid != os.getuid() or DIR.stat().st_mode & 0o077:
        raise ValueError("Approver directory must be owner-only (mode 700)")
    if PRIVATE.is_symlink() or not PRIVATE.is_file() or PRIVATE.stat().st_mode & 0o077:
        raise ValueError("Approver private key must be a non-symlink owner-only file (mode 600)")
    if PRIVATE.stat().st_uid != os.getuid():
        raise ValueError("Approver private key owner mismatch")
    if PUBLIC.is_symlink() or not PUBLIC.is_file() or PUBLIC_HEX.is_symlink():
        raise ValueError("Public key missing or symlinked")


def get_operator_key() -> Ed25519PrivateKey:
    ensure_secure_private()
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


def sign_approval(d: dict, key: Ed25519PrivateKey, now: int, reviewer: str) -> dict:
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


def write_once(path: Path, data: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("Approval document written:", path)
    print("Only this JSON approval document may be transferred; NEVER the private key.")


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
    approval = sign_approval(demo, key, now, "trusted-human")
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
    path = Path(args.draft).resolve(strict=True)
    if not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("Invalid or oversized draft JSON")
    d = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    validate_draft(d, now, issuer=args.issuer, key_id=args.key_id, audience=args.audience)
    digest = hashlib.sha256(canonical({k: v for k, v in d.items() if k != "signature"})).hexdigest()
    print("\nHUMAN APPROVAL — review the actual signed fields:")
    print(json.dumps(d, sort_keys=True, indent=2, ensure_ascii=True))
    print("  canonical draft SHA256:", digest)
    print("  current UTC seconds:", now // 1000)
    if input("Type EXACTLY 'APPROVE add(7,8)' after reviewing: ").strip() != "APPROVE add(7,8)":
        raise ValueError("Human approval not given")
    # Loading the encrypted key can take significant human time. Recheck
    # expiry *after* passphrase entry to avoid emitting stale approvals.
    key = get_operator_key()
    now = int(time.time() * 1000)
    validate_draft(d, now, issuer=args.issuer, key_id=args.key_id, audience=args.audience)
    approval = sign_approval(d, key, now, reviewer=args.reviewer)
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
    p.add_argument("--reviewer", default="trusted-human")
    args = parser.parse_args()
    if args.mode == "self-test":
        test()
    else:
        approve(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Avoid printing exception details which might include user-provided JSON.
        print("DENY: Local approval failed (invalid draft, credentials, or environment)", file=sys.stderr)
        sys.exit(2)
