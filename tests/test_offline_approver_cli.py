from __future__ import annotations
import hashlib
import json
import warnings
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
    approval=mod.sign_approval(d,key,now,'trusted-human',issuer='pilot-issuer',key_id='pilot-key',audience='pilot-kernel')
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
    monkeypatch.setattr(mod,'require_interactive_tty',lambda:None)
    monkeypatch.setattr('builtins.input',lambda prompt:prompt.split("'")[1])
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
    monkeypatch.setattr(mod,'require_interactive_tty',lambda:None)
    monkeypatch.setattr('builtins.input',lambda prompt:prompt.split("'")[1])
    key=Ed25519PrivateKey.generate()
    def delayed_key(*, directory_fd):
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


def test_sign_helper_rejects_rebound_unauthorised_action():
    now = int(time.time() * 1000)
    d = make_draft(now)
    d['action'] = 'wallet.transfer'
    bind(d)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match='add'):
        mod.sign_approval(d, key, now, 'human', issuer='pilot-issuer',
                          key_id='pilot-key', audience='pilot-kernel')


def test_sign_helper_rejects_rebound_wrong_parameters():
    now = int(time.time() * 1000)
    d = make_draft(now)
    d['params'] = {'a': 7, 'b': 9}
    bind(d)
    with pytest.raises(ValueError, match='add'):
        mod.sign_approval(d, Ed25519PrivateKey.generate(), now, 'human',
                          issuer='pilot-issuer', key_id='pilot-key', audience='pilot-kernel')


def test_bounded_draft_read_and_path_swap_prevented(tmp_path):
    f = tmp_path / 'oversize.json'
    f.write_bytes(b'{' + b' ' * 8200 + b'}')
    with pytest.raises(ValueError, match='exceeds'):
        mod.load_draft(str(f))
    target = tmp_path / 'target.json'
    target.write_text('{}')
    link = tmp_path / 'link.json'
    link.symlink_to(target)
    with pytest.raises(OSError):
        mod.load_draft(str(link))
    fifo = tmp_path / 'pipe'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='regular file'):
        mod.load_draft(str(fifo))


def test_world_writable_draft_rejected(tmp_path, monkeypatch):
    f = tmp_path / 'draft.json'
    f.write_text('{}')
    target = f.stat()
    real_fstat = os.fstat

    def writable_metadata(fd):
        metadata = real_fstat(fd)
        if (metadata.st_dev, metadata.st_ino) != (target.st_dev, target.st_ino):
            return metadata
        # Preserve the complete fstat shape, including st_size, because other
        # libraries may also call os.fstat while this test hook is installed.
        values = list(metadata)
        values[0] |= 0o022
        result = os.stat_result(values)
        assert result.st_size == metadata.st_size
        return result

    with monkeypatch.context() as scoped:
        scoped.setattr(mod.os, 'fstat', writable_metadata)
        with pytest.raises(ValueError, match='writable'):
            mod.load_draft(str(f))


def test_non_interactive_confirmation_rejected_before_any_key_access(tmp_path, monkeypatch):
    draft = make_draft(int(time.time() * 1000))
    path = tmp_path / 'draft.json'
    path.write_text(json.dumps(draft))
    monkeypatch.setattr(mod, 'DIR', tmp_path)
    monkeypatch.setattr(mod, 'get_operator_key',
                        lambda: pytest.fail('private key must not be loaded'))
    monkeypatch.setattr('builtins.input',
                        lambda prompt: pytest.fail('input() must not be reached'))
    args = SimpleNamespace(draft=str(path), issuer='pilot-issuer',
                           key_id='pilot-key', audience='pilot-kernel', reviewer='operator')
    terminal = SimpleNamespace(isatty=lambda: True)
    pipe = SimpleNamespace(isatty=lambda: False)
    monkeypatch.setattr(mod, 'sys', SimpleNamespace(stdin=pipe, stdout=terminal,
                                                     stderr=terminal))
    with pytest.raises(ValueError, match='Interactive terminal required'):
        mod.approve(args)
    assert not list(tmp_path.glob('approval-*.json'))


def test_wrong_challenge_fails_before_unlock(tmp_path, monkeypatch):
    draft = make_draft(int(time.time() * 1000))
    path = tmp_path / 'draft.json'
    path.write_text(json.dumps(draft))
    monkeypatch.setattr(mod, 'DIR', tmp_path)
    monkeypatch.setattr(mod, 'require_interactive_tty', lambda: None)
    monkeypatch.setattr('builtins.input', lambda prompt: 'APPROVE add(7,8)')
    monkeypatch.setattr(mod, 'get_operator_key',
                        lambda: pytest.fail('private key accessed before exact permit confirmation'))
    args = SimpleNamespace(draft=str(path), issuer='pilot-issuer',
                           key_id='pilot-key', audience='pilot-kernel', reviewer='operator')
    with pytest.raises(ValueError, match='Human approval not given'):
        mod.approve(args)
    assert not list(tmp_path.glob('approval-*.json'))


def test_exact_challenge_precedes_key_unlock(tmp_path, monkeypatch, capsys):
    draft = make_draft(int(time.time() * 1000))
    path = tmp_path / 'draft.json'
    path.write_text(json.dumps(draft))
    events = []
    monkeypatch.setattr(mod, 'DIR', tmp_path)
    monkeypatch.setattr(mod, 'require_interactive_tty', lambda: None)

    def confirm(prompt):
        rendered = capsys.readouterr().out
        digest = hashlib.sha256(mod.canonical({k: v for k, v in draft.items()
                                                if k != 'signature'})).hexdigest()
        assert 'HUMAN APPROVAL' in rendered
        assert '"action": "add"' in rendered
        assert '"a": 7' in rendered and '"b": 8' in rendered
        assert '"subject": "pilot-agent"' in rendered
        assert '"audience": "pilot-kernel"' in rendered
        assert digest in rendered and draft['permit_id'] in rendered
        expected = 'APPROVE ' + draft['permit_id']
        assert expected in prompt
        events.append('confirm')
        return expected

    def unlock(*, directory_fd):
        events.append('unlock')
        return Ed25519PrivateKey.generate()

    monkeypatch.setattr('builtins.input', confirm)
    monkeypatch.setattr(mod, 'get_operator_key', unlock)
    args = SimpleNamespace(draft=str(path), issuer='pilot-issuer',
                           key_id='pilot-key', audience='pilot-kernel', reviewer='operator')
    mod.approve(args)
    assert events == ['confirm', 'unlock']


def test_getpass_echo_fallback_fails_before_opening_private_file(tmp_path, monkeypatch):
    work = tmp_path / 'approver'
    work.mkdir(mode=0o700)
    private = work / 'approver-private.pem'
    private.write_text('does-not-matter')
    public = work / 'approver-public.pem'
    public.write_text('does-not-matter')
    os.chmod(private, 0o600)
    os.chmod(public, 0o600)
    monkeypatch.setattr(mod, 'DIR', work)
    monkeypatch.setattr(mod, 'PRIVATE', private)
    monkeypatch.setattr(mod, 'PUBLIC', public)
    monkeypatch.setattr(mod, 'PUBLIC_HEX', work / 'approver-public.hex')
    monkeypatch.setattr(mod, 'require_interactive_tty', lambda: None)

    def echo_warning(prompt):
        warnings.warn('terminal echo', mod.getpass.GetPassWarning)
        raise AssertionError('warning must have stopped us')

    monkeypatch.setattr(mod.getpass, 'getpass', echo_warning)
    with pytest.raises(mod.getpass.GetPassWarning):
        mod.get_operator_key()


def test_approval_file_write_failure_is_retryable(tmp_path, monkeypatch):
    path = tmp_path / 'approval.json'
    original = mod._link_unnamed_file
    def broken_link(fd, directory_fd, name):
        raise OSError('injected install failure')
    monkeypatch.setattr(mod, '_link_unnamed_file', broken_link)
    with pytest.raises(OSError, match='injected'):
        mod.write_once(path, {'ok': True})
    assert not path.exists()
    assert not list(tmp_path.glob('.approval-*'))
    monkeypatch.setattr(mod, '_link_unnamed_file', original)
    mod.write_once(path, {'ok': True})
    assert json.loads(path.read_text()) == {'ok': True}
    assert path.stat().st_mode & 0o777 == 0o600


def test_atomic_install_never_overwrites_existing_approval(tmp_path):
    path = tmp_path / 'approval.json'
    path.write_text('existing record')
    with pytest.raises(FileExistsError):
        mod.write_once(path, {'new': True})
    assert path.read_text() == 'existing record'
    assert not list(tmp_path.glob('.approval-*'))


def test_approval_install_fsync_failure_cleans_partial_state(tmp_path, monkeypatch):
    path = tmp_path / 'approval.json'
    original = mod.os.fsync
    counter = {'n': 0}

    def fail_directory_sync(fd):
        counter['n'] += 1
        if counter['n'] == 2:
            raise OSError('injected directory fsync failure')
        return original(fd)

    monkeypatch.setattr(mod.os, 'fsync', fail_directory_sync)
    with pytest.raises(OSError, match='directory fsync failure'):
        mod.write_once(path, {'ok': True})
    assert not path.exists()
    assert not list(tmp_path.glob('.approval-*'))


def test_external_node_crypto_reference_vector():
    """Fixture independently produced by Node 22 createPrivateKey + crypto.sign."""
    now = 1800000000000
    d = make_draft(now)
    d['nonce'] = 'a' * 32
    bind(d)
    assert d['permit_id'] == '9127cd34399edeaa0418da7389e8796204dae18c9fdb3039bf6de045475758f8'
    seed = bytes(range(32))  # Public, nonsecret reference vector only.
    key = Ed25519PrivateKey.from_private_bytes(seed)
    approval = mod.sign_approval(d, key, now, 'trusted-human',
                                 issuer='pilot-issuer', key_id='pilot-key', audience='pilot-kernel')
    assert approval['permit_sha256'] == '9b2bd2b6f1f0fd55e8379c067dc2a25d8611a8ddb0bf893a19f5b8b683136fe7'
    assert approval['signature_hex'] == (
        '5a82a6f0c86c798c3d690962f1fe2225847c7c55799e6d22c9c9b941a0b376d'
        '6653d730969300419757aa5f90e67b29c2f9585699a75e2bc0833a124bf4a2705'
    )


def test_mismatched_public_key_and_hex_identity_rejected(tmp_path, monkeypatch):
    work = tmp_path / 'approver'
    work.mkdir(mode=0o700)
    real = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    private = work / 'approver-private.pem'
    public = work / 'approver-public.pem'
    hexf = work / 'approver-public.hex'
    password = b'temporary-synthetic-password'
    private.write_bytes(real.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.BestAvailableEncryption(password)))
    os.chmod(private, 0o600)
    public.write_bytes(wrong.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    hexf.write_text(wrong.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    os.chmod(public, 0o600)
    os.chmod(hexf, 0o600)
    monkeypatch.setattr(mod, 'DIR', work)
    monkeypatch.setattr(mod, 'PRIVATE', private)
    monkeypatch.setattr(mod, 'PUBLIC', public)
    monkeypatch.setattr(mod, 'PUBLIC_HEX', hexf)
    monkeypatch.setattr(mod, 'require_interactive_tty', lambda: None)
    monkeypatch.setattr(mod.getpass, 'getpass', lambda prompt: password.decode())
    with pytest.raises(ValueError, match='Private and public keys disagree'):
        mod.get_operator_key()
    public.write_bytes(real.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ValueError, match='Hex public identity mismatch'):
        mod.get_operator_key()
    assert not list(work.glob('approval-*.json'))


def test_failed_file_fsync_cleans_temporary_and_allows_retry(tmp_path, monkeypatch):
    dest = tmp_path / 'approval.json'
    original_fsync = mod.os.fsync

    def broken_fsync(fd):
        raise OSError('injected flush failure')

    monkeypatch.setattr(mod.os, 'fsync', broken_fsync)
    with pytest.raises(OSError, match='injected flush failure'):
        mod.write_once(dest, {'ok': True})
    assert not dest.exists()
    assert not list(tmp_path.glob('.approval-*'))
    monkeypatch.setattr(mod.os, 'fsync', original_fsync)
    mod.write_once(dest, {'ok': True})
    assert json.loads(dest.read_text()) == {'ok': True}


def test_hidden_review_output_is_rejected_before_approval(monkeypatch):
    terminal = SimpleNamespace(isatty=lambda: True)
    hidden = SimpleNamespace(isatty=lambda: False)
    monkeypatch.setattr(mod, 'sys', SimpleNamespace(stdin=terminal, stdout=hidden,
                                                     stderr=terminal))
    with pytest.raises(ValueError, match='Interactive terminal required'):
        mod.require_interactive_tty()


def test_noninteger_approval_timestamps_denied():
    now = int(time.time() * 1000)
    draft = make_draft(now)
    key = Ed25519PrivateKey.generate()
    for invalid in (True, False, None, 3.14, '1700000000000', 2**53, -1):
        with pytest.raises(ValueError, match='timestamp'):
            mod.sign_approval(draft, key, invalid, 'human', issuer='pilot-issuer',
                              key_id='pilot-key', audience='pilot-kernel')


def test_approval_expiring_while_fsync_denied_before_link(tmp_path, monkeypatch):
    now_ms = int(time.time() * 1000)
    data = {'schema': 'shards.operator-approval.v1', 'expires_at_ms': now_ms + 15_000}
    target = tmp_path / 'approval.json'
    original = mod.os.fsync
    called = {'n': 0}

    def slow_fsync(fd):
        called['n'] += 1
        result = original(fd)
        monkeypatch.setattr(mod.time, 'time', lambda: (now_ms + 16_000) / 1000)
        return result

    monkeypatch.setattr(mod.os, 'fsync', slow_fsync)
    with pytest.raises(ValueError, match='expired before publication'):
        mod.write_once(target, data)
    assert called['n'] >= 1
    assert not target.exists()


def test_unnamed_inode_installation_resists_temporary_path_substitution(tmp_path, monkeypatch):
    target = tmp_path / 'approval.json'
    real_link = mod._link_unnamed_file
    observed = {'invoked': False}

    def simulate_attacker(fd, dirfd, filename):
        # No temporary filename exists to replace: the only publication source
        # is the open unnamed inode represented by fd.
        observed['invoked'] = True
        assert os.fstat(fd).st_nlink == 0
        assert not list(tmp_path.glob('.approval-*'))
        (tmp_path / '.approval-guess.tmp').write_text('attacker-controlled')
        real_link(fd, dirfd, filename)

    monkeypatch.setattr(mod, '_link_unnamed_file', simulate_attacker)
    mod.write_once(target, {'safe': True})
    assert observed['invoked']
    assert json.loads(target.read_text()) == {'safe': True}


def test_preexisting_approval_path_blocks_unnamed_install(tmp_path):
    target = tmp_path / 'approval.json'
    target.write_text('existing target')
    with pytest.raises(FileExistsError):
        mod.write_once(target, {'safe': True})
    assert target.read_text() == 'existing target'


def test_swap_of_checked_output_directory_is_denied(tmp_path, monkeypatch):
    original = tmp_path / 'approver'
    original.mkdir(mode=0o700)
    moved = tmp_path / 'moved-approver'
    directory_fd = mod._secure_directory_fd(original)
    try:
        original.rename(moved)
        original.mkdir(mode=0o700)
        with pytest.raises(ValueError, match='directory changed'):
            mod.write_once(original / 'approval.json', {'safe': True}, directory_fd=directory_fd)
        assert not (original / 'approval.json').exists()
        assert not (moved / 'approval.json').exists()
    finally:
        os.close(directory_fd)


def test_swap_after_staging_denies_before_publication(tmp_path, monkeypatch):
    directory = tmp_path / 'approver'
    directory.mkdir(mode=0o700)
    moved = tmp_path / 'moved-approver'
    original = mod.os.fsync
    swapped = {'done': False}

    def swap_after_staging(fd):
        result = original(fd)
        if not swapped['done']:
            swapped['done'] = True
            directory.rename(moved)
            directory.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(mod.os, 'fsync', swap_after_staging)
    with pytest.raises(ValueError, match='directory changed'):
        mod.write_once(directory / 'approval.json', {'safe': True})
    assert not (directory / 'approval.json').exists()
    assert not (moved / 'approval.json').exists()


def test_insecure_or_symlink_approval_directory_denied(tmp_path):
    directory = tmp_path / 'approver'
    directory.mkdir(mode=0o700)
    link = tmp_path / 'pointer'
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        mod.write_once(link / 'approval.json', {'safe': True})
    os.chmod(directory, 0o777)
    try:
        with pytest.raises(ValueError, match='owner-only'):
            mod.write_once(directory / 'approval.json', {'safe': True})
    finally:
        os.chmod(directory, 0o700)
    assert not (directory / 'approval.json').exists()
