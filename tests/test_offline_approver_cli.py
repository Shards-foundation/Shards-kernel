from __future__ import annotations
import hashlib
import json
import os
import secrets
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools import offline_approver as mod


def make_draft(now):
    d = {
        'permit_id':'', 'issuer':'pilot-issuer', 'subject':'pilot-agent',
        'jurisdiction':'default','action':'add','params':{'a':7,'b':8},
        'constraints':{}, 'max_executions':1, 'valid_from_ms':now-500,
        'valid_until_ms':now+120_000, 'evidence_hash':'',
        'proposal_hash':'f'*64,'nonce':secrets.token_hex(16),'signature':'',
        'key_id':'pilot-key','version':2,'algorithm':'Ed25519','audience':'pilot-kernel'
    }
    bind(d)
    return d


def bind(d):
    d['permit_id'] = hashlib.sha256(mod.canonical({k:v for k,v in d.items() if k not in ('permit_id','signature')})).hexdigest()


def validate(d, now):
    mod.validate_draft(d, now, issuer='pilot-issuer',key_id='pilot-key',audience='pilot-kernel')


def test_self_test(capsys):
    mod.test()
    assert 'tamper denial' in capsys.readouterr().out


def test_signed_approval_matches_canonical_domain():
    now=int(time.time()*1000)
    d=make_draft(now)
    key=Ed25519PrivateKey.generate()
    approval=mod.sign_approval(d,key,now,'trusted-human')
    signed=mod.APPROVAL_DOMAIN+mod.canonical({k:v for k,v in approval.items() if k!='signature_hex'})
    key.public_key().verify(bytes.fromhex(approval['signature_hex']), signed)
    assert approval['permit_id']==d['permit_id']
    assert len(approval['signature_hex'])==128
    assert approval['expires_at_ms']-now==60_000


@pytest.mark.parametrize('change', [
    lambda d: d.update(action='wallet.transfer'),
    lambda d: d.update(params={'a':7,'b':9}),
    lambda d: d.update(params={'a':True,'b':8}),
    lambda d: d.update(params={'a':7,'b':8,'extra':1}),
    lambda d: d.update(max_executions=2),
    lambda d: d.update(max_executions=True),
    lambda d: d.update(constraints={'allowed_domains':['*']}),
    lambda d: d.update(audience='other-kernel'),
    lambda d: d.update(issuer='other-issuer'),
    lambda d: d.update(key_id='another-key'),
    lambda d: d.update(version=1),
    lambda d: d.update(signature='a'*128),
    lambda d: d.update(nonce='short'),
    lambda d: d.update(proposal_hash='abc*'),
    lambda d: d.update(evidence_hash='abc'),
    lambda d: d.update(valid_until_ms=d['valid_from_ms']+900_001),
    lambda d: d.update(valid_from_ms=d['valid_until_ms']+1000),
    lambda d: d.update(subject='evil\ud800'),
    lambda d: d.update(params={'a':7.0,'b':8}),
    lambda d: d.update(permit_id='0'*64),
    lambda d: d.update(other_field='unexpected'),
])
def test_denials(change):
    now=int(time.time()*1000)
    d=make_draft(now)
    change(d)
    with pytest.raises((ValueError,KeyError,TypeError)):
        validate(d,now)


def test_tamper_after_rebinding_denied():
    now=int(time.time()*1000)
    d=make_draft(now)
    d['action']='wallet.transfer'
    bind(d)
    with pytest.raises(ValueError,match='add'):
        validate(d,now)


def test_duplicate_json_rejected():
    with pytest.raises(ValueError,match='Duplicate'):
        json.loads('{"x":1,"x":2}',object_pairs_hook=mod.no_duplicates)


def test_canonical_non_js_numbers_rejected():
    with pytest.raises(ValueError):
        mod.canonical({'n':2**53})
    with pytest.raises(ValueError):
        mod.canonical({'n':float('nan')})
    with pytest.raises(ValueError):
        mod.canonical({'text':'\ud800'})


def test_real_approve_path_with_encrypted_ephemeral_key(tmp_path,monkeypatch):
    work=tmp_path/'offline'
    work.mkdir(mode=0o700)
    key=Ed25519PrivateKey.generate()
    password=b'ephemeral-test-passphrase-not-real'
    private=work/'approver-private.pem'
    public=work/'approver-public.pem'
    hexf=work/'approver-public.hex'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password)))
    os.chmod(private,0o600)
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    hexf.write_text(raw.hex())
    for x in (public,hexf):
        os.chmod(x,0o600)
    monkeypatch.setattr(mod,'DIR',work)
    monkeypatch.setattr(mod,'PRIVATE',private)
    monkeypatch.setattr(mod,'PUBLIC',public)
    monkeypatch.setattr(mod,'PUBLIC_HEX',hexf)
    monkeypatch.setattr(mod.getpass,'getpass',lambda prompt:password.decode())
    monkeypatch.setattr('builtins.input',lambda prompt:'APPROVE add(7,8)')
    now=int(time.time()*1000)
    d=make_draft(now)
    f=tmp_path/'draft.json'
    f.write_text(json.dumps(d))
    args=SimpleNamespace(draft=str(f),issuer='pilot-issuer',key_id='pilot-key',audience='pilot-kernel',reviewer='trusted-human')
    mod.approve(args)
    approval=work/f"approval-{d['permit_id'][:16]}.json"
    assert approval.is_file()
    assert approval.stat().st_mode & 0o777 == 0o600
    a=json.loads(approval.read_text())
    key.public_key().verify(bytes.fromhex(a['signature_hex']), mod.APPROVAL_DOMAIN+mod.canonical({k:v for k,v in a.items() if k!='signature_hex'}))
    assert a['permit_sha256']==hashlib.sha256(mod.canonical({k:v for k,v in d.items() if k!='signature'})).hexdigest()
    with pytest.raises(FileExistsError):
        mod.approve(args)
    assert private.exists() and private.stat().st_size > 100


def test_passphrase_delay_causes_rejection_no_signed_output(tmp_path,monkeypatch):
    work=tmp_path/'offline'
    work.mkdir(mode=0o700)
    monkeypatch.setattr(mod,'DIR',work)
    now=int(time.time()*1000)
    d=make_draft(now)
    f=tmp_path/'draft.json'
    f.write_text(json.dumps(d))
    monkeypatch.setattr('builtins.input',lambda prompt:'APPROVE add(7,8)')
    key=Ed25519PrivateKey.generate()
    def delayed_key():
        monkeypatch.setattr(mod.time,'time',lambda:(now+130_000)/1000)
        return key
    monkeypatch.setattr(mod,'get_operator_key',delayed_key)
    args=SimpleNamespace(draft=str(f),issuer='pilot-issuer',key_id='pilot-key',audience='pilot-kernel',reviewer='trusted-human')
    try:
        with pytest.raises(ValueError,match='Permit not currently valid'):
            mod.approve(args)
        assert not list(work.glob('approval-*.json'))
    finally:
        monkeypatch.undo()
