#!/usr/bin/env python3
"""Termux-side Phase 3 verifier-only Qwen3 agent.

Never imports private signing primitives. Never reads operator.key.
Existing v2 installation and audit remain untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import stat
import sys

import agent_tools as local_tools  # pure verifier-side tools, never a signer
from implementations.storage import SQLiteAuditStorage
from shards_kernel.api import (
    Decision, JurisdictionPolicy, KernelConfig, KernelRequest, ReceiptStatus,
    StrictKernel, ToolCall, replay_and_verify,
)
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.time import PersistentSystemClock
from shards_kernel.integrations.generic_adapter import GenericAdapter
from shards_kernel.permits import PermitToken, PublicVerificationKey
from phase3_protocol import (
    ACTOR, ALLOWED, ISSUER, KEY_ID, KERNEL_ID, canonical, make_proposal,
    proposal_hash, read_json_file, validate_proposal, validate_tool, write_new_file,
)

ROOT = Path.home() / '.shards-qwen3-v3'
LEGACY_PHASE2_ROOT = Path.home() / '.shards-qwen3-v2'


def ensure_root(root: Path):
    if root.is_symlink():
        raise ValueError('State directory cannot be a symlink')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError('State directory requires 0700 permissions')


def enroll(root: Path, hex_public: str, fingerprint: str):
    ensure_root(root)
    public = bytes.fromhex(hex_public)
    if len(public) != 32 or hashlib.sha256(public).hexdigest() != fingerprint.lower():
        raise ValueError('Public-key fingerprint mismatch; verify with the operator out of band')
    key_path = root / 'operator-v3.pub'
    if key_path.exists() or key_path.is_symlink():
        raise ValueError('Operator public key already enrolled; refusing silent replacement')
    workspace = root / 'workspace'
    if workspace.is_symlink():
        raise ValueError('Workspace cannot be a symlink')
    workspace.mkdir(mode=0o700, exist_ok=True)
    if not workspace.is_dir():
        raise ValueError('Workspace must be a real directory')
    db = root / 'audit-v3.sqlite3'
    if db.is_symlink() or (db.exists() and not db.is_file()):
        raise ValueError('Audit database must be a regular file')
    SQLiteAuditStorage(str(db))
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS agent_memory '
                     '(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ms INTEGER NOT NULL)')
    # Publish trust only after everything else has been installed successfully.
    # A setup failure leaves no enrolled identity and can be retried safely.
    write_new_file(key_path, public)
    print('ENROLLED: verifier-only Phase 3; no signing key installed')
    print('PUBLIC_KEY_SHA256:', fingerprint.lower())
    print('EXISTING PHASE 2 FILES WERE NOT MODIFIED.')


def launch(root: Path):
    pub_path = root / 'operator-v3.pub'
    db = root / 'audit-v3.sqlite3'
    if (not pub_path.is_file() or pub_path.is_symlink() or
            not db.is_file() or db.is_symlink()):
        raise ValueError('Run enroll with a trusted remote issuer public key first')
    pub = pub_path.read_bytes()
    if len(pub) != 32:
        raise ValueError('Invalid public verifier')
    storage = SQLiteAuditStorage(str(db))
    clock = PersistentSystemClock(str(db), KERNEL_ID)
    kernel = StrictKernel(audit_storage=storage)
    kernel.set_public_verifiers({KEY_ID: PublicVerificationKey(
        issuer=ISSUER, audience=KERNEL_ID, public_key=pub,
    )})
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({ACTOR}), allowed_tools=ALLOWED, allow_intent_only=False,
    ))
    kernel.boot(KernelConfig(kernel_id=KERNEL_ID, variant='strict', clock=clock))
    adapter = GenericAdapter(kernel, actor=ACTOR)
    adapter.register_tool('list_notes', lambda: local_tools.list_notes(root / 'workspace'))
    adapter.register_tool('read_note', lambda name: local_tools.safe_read_note(root / 'workspace', name))
    adapter.register_tool('remember', lambda key, value: local_tools.remember(db, key, value))
    adapter.register_tool('recall', lambda key: local_tools.recall(db, key))
    return kernel, clock


def new_proposal(root: Path, tool: str, params: dict):
    ensure_root(root)
    data = make_proposal(tool, params)
    request_path = root / ('proposal-' + data['proposal_id'] + '.json')
    write_new_file(request_path, canonical(data) + b'\n')
    print('PROPOSAL FILE:', request_path)
    print('REQUEST:', canonical(data).decode())
    print('TRANSFER THIS FILE TO THE PROTECTED ISSUER HOST FOR APPROVAL.')
    return request_path


def check_audit(kernel):
    evidence = kernel.export_evidence()
    entries = [audit_entry_to_dict(entry) for entry in evidence.ledger_entries]
    ok, errors = replay_and_verify(entries, evidence.root_hash)
    print('AUDIT:', 'PASS' if ok else 'FAIL', 'entries:', len(entries))
    print('ROOT:', evidence.root_hash)
    if errors:
        print('ERRORS:', errors)
    return bool(ok)


def execute(root: Path, proposal_file: Path, permit_file: Path):
    # Freshness is enforced before operator signing. At execution the signed
    # permit expiry is authoritative; the proposal hash binds exact content.
    proposal = validate_proposal(read_json_file(proposal_file), check_age=False)
    raw_permit = read_json_file(permit_file)
    if type(raw_permit) is not dict:
        raise ValueError('Invalid permit file')
    permit = PermitToken(**raw_permit)
    # Defense in depth. Kernel independently verifies the full Ed25519 permit.
    if (permit.version != 2 or permit.algorithm != 'Ed25519' or
        permit.issuer != ISSUER or permit.audience != KERNEL_ID or
        permit.subject != ACTOR or permit.key_id != KEY_ID or
        permit.action != proposal['tool'] or
        canonical(permit.params) != canonical(proposal['params']) or
        permit.proposal_hash != proposal_hash(proposal) or
        permit.max_executions != 1):
        raise ValueError('Signed permit does not match exact proposal')
    kernel, clock = launch(root)
    params = proposal['params']
    r = kernel.submit(KernelRequest(
        request_id=proposal['proposal_id'], ts_ms=clock.now_ms(),
        actor=ACTOR, intent='Execute independently approved local tool',
        tool_call=ToolCall(name=proposal['tool'], params=dict(params)),
        params=dict(params),
    ), permit_token=permit)
    print('DECISION:', r.decision.value)
    print('RESULT:', json.dumps(r.tool_result, ensure_ascii=False))
    print('ERROR:', r.error)
    if not check_audit(kernel):
        raise RuntimeError('Audit integrity failed')
    return r


def main():
    ap = argparse.ArgumentParser(description='Qwen3 governed agent, verifier-only Phase 3')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('status')
    sub.add_parser('audit')
    enroll_cmd = sub.add_parser('enroll')
    enroll_cmd.add_argument('public_key_hex')
    enroll_cmd.add_argument('expected_sha256')
    pro = sub.add_parser('propose')
    pro.add_argument('tool')
    pro.add_argument('params_json')
    ask = sub.add_parser('ask')
    ask.add_argument('prompt', nargs='+')
    exe = sub.add_parser('execute')
    exe.add_argument('proposal', type=Path)
    exe.add_argument('permit', type=Path)
    args = ap.parse_args()
    if args.cmd == 'enroll':
        enroll(ROOT, args.public_key_hex, args.expected_sha256)
    elif args.cmd == 'status':
        print('VERIFIER ENROLLED:', (ROOT / 'operator-v3.pub').is_file())
        print('PRIVATE SIGNER IN PHASE 3:', (ROOT / 'issuer-private.key').exists())
        print('PHASE 2 INTACT:', LEGACY_PHASE2_ROOT.is_dir())
        print('PHASE 2 SIGNING KEY STILL ON PHONE:', (LEGACY_PHASE2_ROOT / 'operator.key').exists())
        print('HOST SEPARATION: requires an independently protected issuer host')
    elif args.cmd == 'audit':
        k, _ = launch(ROOT)
        if not check_audit(k):
            return 2
    elif args.cmd == 'propose':
        new_proposal(ROOT, *validate_tool(args.tool, json.loads(args.params_json)))
    elif args.cmd == 'ask':
        # Model is only asked for JSON tool proposals, never given signer access.
        actions = local_tools.ask_model(' '.join(args.prompt))
        if not actions:
            print('No permissible actions proposed')
        for tool, params in actions:
            new_proposal(ROOT, tool, params)
    elif args.cmd == 'execute':
        r = execute(ROOT, args.proposal, args.permit)
        if r.decision != Decision.ALLOW or r.status != ReceiptStatus.ACCEPTED or r.error:
            return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, TypeError, KeyError, IndexError, OSError, RuntimeError,
            sqlite3.Error, json.JSONDecodeError) as exc:
        print('FAIL CLOSED:', type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(2)
