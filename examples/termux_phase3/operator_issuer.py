#!/usr/bin/env python3
"""Human-operated offline issuer. RUN ONLY ON A SEPARATELY PROTECTED HOST.

Requires pip install shards-kernel[crypto]==0.1.3. No listening service,
cloud credentials or untrusted remote signing endpoints.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel.api import PermitBuilder
from shards_kernel.issuer import sign_v2_permit

from phase3_protocol import (
    ACTOR, ISSUER, KEY_ID, KERNEL_ID, canonical, proposal_hash,
    read_json_file, validate_proposal, write_new_file,
)


def load_private(home: Path):
    path = home / 'issuer-private.key'
    if path.is_symlink():
        raise ValueError('Refusing symlinked issuer key')
    meta = path.stat()
    if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600:
        raise ValueError('Issuer key must be a private 0600 regular file')
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def init(home: Path):
    if home.is_symlink():
        raise ValueError('Home cannot be a symlink')
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(home.stat().st_mode) != 0o700:
        raise ValueError('Issuer home must be mode 0700')
    if (home / 'issuer-private.key').exists() or (home / 'issuer-public.bin').exists():
        raise ValueError('Issuer already initialised; refusing key replacement')
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                   serialization.NoEncryption())
    pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_path = home / 'issuer-private.key'
    private_created = False
    try:
        write_new_file(private_path, secret)
        private_created = True
        write_new_file(home / 'issuer-public.bin', pub)
    except Exception:
        # Remove only the key successfully created by THIS attempt; never
        # unlink a pre-existing path if its exclusive creation was refused.
        if private_created:
            try:
                private_path.unlink(missing_ok=True)
            except OSError:
                pass  # Preserve the initial failure; retry refuses partial keys.
        raise
    print('ISSUER INITIALISED')
    print('PUBLIC_KEY_HEX:', pub.hex())
    print('PUBLIC_KEY_SHA256:', hashlib.sha256(pub).hexdigest())
    print('KEEP THE PRIVATE KEY ON THIS HOST ONLY.')


def issue(home: Path, proposal_file: Path, permit_file: Path):
    private = load_private(home)
    raw = read_json_file(proposal_file)
    proposal = validate_proposal(raw)
    pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_pub = (home / 'issuer-public.bin').read_bytes()
    if expected_pub != pub:
        raise ValueError('Public/private issuer key mismatch')
    print('PROPOSAL ID:', proposal['proposal_id'])
    print('ACTION:', proposal['tool'])
    # Display approval data with Unicode/control characters escaped to
    # prevent bidi and invisible-character deception. Signing remains exact.
    print('EXACT PARAMETERS (escaped):', json.dumps(
        proposal['params'], sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ))
    print('PROPOSAL SHA256:', proposal_hash(proposal))
    print('AUDIENCE:', KERNEL_ID, 'ACTOR:', ACTOR)
    confirmation = input('Type APPROVE to sign ONE execution: ')
    if confirmation != 'APPROVE':
        raise ValueError('Operator declined; permit not issued')
    # Recheck after input: no signature for stale request or modified file.
    fresh = read_json_file(proposal_file)
    if canonical(fresh) != canonical(proposal):
        raise ValueError('Proposal changed during approval')
    validate_proposal(fresh)
    now = time.time_ns() // 1_000_000
    unsigned = (
        PermitBuilder().issuer(ISSUER).subject(ACTOR).jurisdiction('default')
        .action(proposal['tool']).params(proposal['params']).constraints({})
        .max_executions(1).valid_from_ms(now - 1_000)
        .valid_until_ms(now + 5 * 60_000)
        .evidence_hash('').proposal_hash(proposal_hash(proposal))
        .build_unsigned_v2(key_id=KEY_ID, audience=KERNEL_ID)
    )
    signed = sign_v2_permit(unsigned, private)
    write_new_file(permit_file, canonical(asdict(signed)) + b'\n')
    print('SIGNED PERMIT:', permit_file)
    print('PERMIT EXPIRES IN 5 MINUTES. TRANSFER TO PHONE IMMEDIATELY.')


def main():
    ap = argparse.ArgumentParser(description='Offline Shards permit issuer; separate host only')
    ap.add_argument('--home', type=Path, default=Path.home() / '.shards-offline-issuer')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init')
    sub.add_parser('public')
    issue_p = sub.add_parser('issue')
    issue_p.add_argument('proposal', type=Path)
    issue_p.add_argument('permit', type=Path)
    args = ap.parse_args()
    if args.cmd == 'init':
        init(args.home)
    elif args.cmd == 'public':
        pub = (args.home / 'issuer-public.bin').read_bytes()
        if len(pub) != 32:
            raise ValueError('Invalid issuer public key')
        print('PUBLIC_KEY_HEX:', pub.hex())
        print('PUBLIC_KEY_SHA256:', hashlib.sha256(pub).hexdigest())
    else:
        issue(args.home, args.proposal, args.permit)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('ISSUER DENIED:', type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(2)
