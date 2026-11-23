"""Shared, dependency-free protocol for Phase 3 offline-issued permits.

Only fixed read-only/local-memory tools can be proposed. No dynamic Python,
commands, arbitrary paths, network tools or unrestricted environment access.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any

KERNEL_ID = 'termux-qwen3-v3'
ACTOR = 'qwen3-local'
ISSUER = 'shards-offline-operator-v1'
KEY_ID = 'shards-offline-operator-key-v1'
SCHEMA = 'shards.offline-tool-proposal.v1'
MAX_AGE_MS = 15 * 60_000
ALLOWED = frozenset({'echo', 'add', 'list_notes', 'read_note', 'remember', 'recall'})
NOTE_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.(?:md|txt|json)\Z')
KEY_PATTERN = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
UUID_PATTERN = re.compile(r'[0-9a-f]{32}\Z')


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


_PARAMETER_SHAPES = {
    'add': {'a', 'b'}, 'echo': {'text'}, 'list_notes': set(),
    'read_note': {'name'}, 'remember': {'key', 'value'}, 'recall': {'key'},
}


def _validate_add(params: dict) -> None:
    if any(type(params[key]) is not int or abs(params[key]) > 1_000_000
           for key in ('a', 'b')):
        raise ValueError('add arguments must be bounded integers')


def _validate_echo(params: dict) -> None:
    if type(params['text']) is not str or not 1 <= len(params['text']) <= 200:
        raise ValueError('Invalid echo text')


def _validate_note(params: dict) -> None:
    name = params['name']
    if type(name) is not str or not NOTE_PATTERN.fullmatch(name) or '..' in name:
        raise ValueError('Invalid note name')


def _validate_memory_key(params: dict) -> None:
    key = params['key']
    if type(key) is not str or not KEY_PATTERN.fullmatch(key):
        raise ValueError('Invalid memory key')


def _validate_remember(params: dict) -> None:
    _validate_memory_key(params)
    value = params['value']
    if type(value) is not str or not 1 <= len(value) <= 500:
        raise ValueError('Invalid memory value')


_PARAM_VALIDATORS = {
    'add': _validate_add, 'echo': _validate_echo, 'read_note': _validate_note,
    'remember': _validate_remember, 'recall': _validate_memory_key,
}


def validate_tool(tool: Any, params: Any) -> tuple[str, dict]:
    if type(tool) is not str or tool not in ALLOWED or type(params) is not dict:
        raise ValueError('Unknown tool or malformed parameters')
    if set(params) != _PARAMETER_SHAPES[tool]:
        raise ValueError('Unexpected/missing tool parameters')
    validator = _PARAM_VALIDATORS.get(tool)
    if validator is not None:
        validator(params)
    # Enforce JSON serializability and no NaN or other non-JSON values.
    canonical(params)
    return tool, dict(params)


def make_proposal(tool: str, params: dict, *, now: int | None = None) -> dict:
    tool, params = validate_tool(tool, params)
    if now is None:
        now = time.time_ns() // 1_000_000
    return {
        'schema': SCHEMA, 'proposal_id': uuid.uuid4().hex,
        'kernel_id': KERNEL_ID, 'actor': ACTOR,
        'tool': tool, 'params': params, 'created_ms': now,
    }


def validate_proposal(proposal: Any, *, now: int | None = None, check_age: bool = True) -> dict:
    if type(proposal) is not dict or set(proposal) != {
        'schema', 'proposal_id', 'kernel_id', 'actor', 'tool', 'params', 'created_ms'
    }:
        raise ValueError('Invalid proposal envelope')
    if (proposal['schema'] != SCHEMA or proposal['kernel_id'] != KERNEL_ID or
        proposal['actor'] != ACTOR or type(proposal['proposal_id']) is not str or
        not UUID_PATTERN.fullmatch(proposal['proposal_id'])):
        raise ValueError('Proposal identity mismatch')
    if type(proposal['created_ms']) is not int or proposal['created_ms'] < 0:
        raise ValueError('Invalid proposal timestamp')
    if now is None:
        now = time.time_ns() // 1_000_000
    if check_age and not (now - MAX_AGE_MS <= proposal['created_ms'] <= now + 10_000):
        raise ValueError('Proposal stale or from the future')
    validate_tool(proposal['tool'], proposal['params'])
    if len(canonical(proposal)) > 4_096:
        raise ValueError('Proposal too large')
    return proposal


def proposal_hash(proposal: dict) -> str:
    return hashlib.sha256(canonical(proposal)).hexdigest()


def read_json_file(path, max_bytes: int = 16_384):
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > max_bytes:
            raise ValueError('Input must be a small regular file')
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ValueError('Input exceeds size limit')
    return json.loads(data.decode('utf-8'))


def write_new_file(path, data: bytes) -> None:
    import os
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        # The exclusive file was created by this call; do not strand a partial
        # permit, proposal, or key if a disk/flush/fsync operation fails.
        try:
            os.unlink(path)
        except OSError:
            pass  # Preserve the original failure.
        raise
