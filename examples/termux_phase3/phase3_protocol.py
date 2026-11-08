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


def validate_tool(tool: Any, params: Any) -> tuple[str, dict]:
    if type(tool) is not str or tool not in ALLOWED or type(params) is not dict:
        raise ValueError('Unknown tool or malformed parameters')
    shapes = {'add': {'a', 'b'}, 'echo': {'text'}, 'list_notes': set(),
              'read_note': {'name'}, 'remember': {'key', 'value'}, 'recall': {'key'}}
    if set(params) != shapes[tool]:
        raise ValueError('Unexpected/missing tool parameters')
    if tool == 'add':
        if any(type(params[k]) is not int or abs(params[k]) > 1_000_000 for k in ('a', 'b')):
            raise ValueError('add arguments must be bounded integers')
    elif tool == 'echo':
        if type(params['text']) is not str or not 1 <= len(params['text']) <= 200:
            raise ValueError('Invalid echo text')
    elif tool == 'read_note':
        if (type(params['name']) is not str or
            not NOTE_PATTERN.fullmatch(params['name']) or '..' in params['name']):
            raise ValueError('Invalid note name')
    elif tool in ('remember', 'recall'):
        if type(params['key']) is not str or not KEY_PATTERN.fullmatch(params['key']):
            raise ValueError('Invalid memory key')
        if tool == 'remember':
            if type(params['value']) is not str or not 1 <= len(params['value']) <= 500:
                raise ValueError('Invalid memory value')
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


def validate_proposal(proposal: Any, *, now: int | None = None) -> dict:
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
    if not (now - MAX_AGE_MS <= proposal['created_ms'] <= now + 10_000):
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
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
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
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
