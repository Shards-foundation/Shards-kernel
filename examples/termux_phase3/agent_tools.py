"""Verifier-side local tools and Qwen proposal parser for the Phase 3 pilot.

This module contains NO signing key handling, permit issuance, operator approval
or automatic execution authority. The external issuer holds all private keys.
Network access is restricted to a configured local model endpoint; redirects and
system HTTP proxies are explicitly disabled.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any
import urllib.request

from phase3_protocol import NOTE_PATTERN, validate_tool

MODEL_HOST = "http://127.0.0.1:8080"
MAX_ACTIONS = 3
MAX_MODEL_RESPONSE_BYTES = 65_536


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("LOCAL_MODEL_REDIRECT_DENIED")


_LOCAL_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _RejectRedirect()
)


def _open_json(path: str, *, body: bytes | None = None, timeout: int = 10) -> Any:
    if path not in ("/v1/models", "/v1/chat/completions"):
        raise ValueError("LOCAL_MODEL_ENDPOINT_NOT_ALLOWED")
    url = MODEL_HOST + path
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, data=body, headers=headers)
    with _LOCAL_OPENER.open(request, timeout=timeout) as response:
        raw = response.read(MAX_MODEL_RESPONSE_BYTES + 1)
    if len(raw) > MAX_MODEL_RESPONSE_BYTES:
        raise ValueError("LOCAL_MODEL_RESPONSE_TOO_LARGE")
    return json.loads(raw.decode("utf-8"))


def parse_plan(text: str) -> list[tuple[str, dict[str, Any]]]:
    if type(text) is not str or len(text) > 10_000:
        raise ValueError("Malformed or oversized model output")
    data = json.loads(text)
    if type(data) is not dict or set(data) != {"actions"}:
        raise ValueError("Expected exact actions object")
    actions = data["actions"]
    if type(actions) is not list or len(actions) > MAX_ACTIONS:
        raise ValueError("Too many actions or malformed plan")
    parsed: list[tuple[str, dict[str, Any]]] = []
    for action in actions:
        if type(action) is not dict or set(action) != {"tool", "params"}:
            raise ValueError("Malformed action object")
        tool, params = validate_tool(action["tool"], action["params"])
        parsed.append((tool, params))
    return parsed


def ask_model(prompt: str) -> list[tuple[str, dict[str, Any]]]:
    """Request only JSON action proposals; never grant authority to the model."""
    if type(prompt) is not str or not 1 <= len(prompt) <= 4_000:
        raise ValueError("Invalid or oversized prompt")
    models = _open_json("/v1/models", timeout=10)
    entries = models.get("data") if isinstance(models, dict) else None
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        raise ValueError("MODEL_LIST_EMPTY_OR_INVALID")
    model = entries[0].get("id")
    if not isinstance(model, str) or not model:
        raise ValueError("MODEL_ID_MISSING")

    instruction = (
        "You only propose tool calls; you cannot approve or issue permits. "
        "Respond with JSON only, e.g. "
        '{"actions":[{"tool":"add","params":{"a":2,"b":3}}]}. '
        "Allowed: add(a,b), echo(text), list_notes(), read_note(name), "
        "remember(key,value), recall(key). Maximum three actions. "
        'For unknown requests return {"actions":[]}. '
        "Do not include code, shell commands, reasoning, or markdown."
    )
    body = json.dumps({
        "model": model,
        "stream": False,
        "temperature": 0,
        "max_tokens": 450,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": prompt},
        ],
    }).encode("utf-8")
    completion = _open_json("/v1/chat/completions", body=body, timeout=180)
    choices = completion.get("choices") if isinstance(completion, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("MODEL_COMPLETION_EMPTY_OR_INVALID")
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise ValueError("MODEL_COMPLETION_CONTENT_INVALID")
    return parse_plan(content)


def safe_read_note(workspace: Path, name: str) -> str:
    validate_tool("read_note", {"name": name})
    # Directory descriptor + single basename + O_NOFOLLOW prevents traversal.
    directory_fd = os.open(
        workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > 8192:
                raise ValueError("Not a regular note or note is too large")
            data = os.read(fd, 8193)
            if len(data) > 8192:
                raise ValueError("Note exceeds 8 KiB")
            return data.decode("utf-8", errors="strict")
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def list_notes(workspace: Path) -> list[str]:
    names = []
    for entry in workspace.iterdir():
        name = entry.name
        if (
            NOTE_PATTERN.fullmatch(name) and ".." not in name
            and not entry.is_symlink() and entry.is_file()
            and entry.stat().st_nlink == 1
        ):
            names.append(name)
    return sorted(names)[:50]


def _check_db(db: Path) -> None:
    if db.is_symlink() or not db.is_file():
        raise ValueError("Audit/memory database must be an enrolled regular file")


def recall(db: Path, key: str) -> str | None:
    validate_tool("recall", {"key": key})
    _check_db(db)
    with sqlite3.connect(db) as connection:
        row = connection.execute(
            "SELECT value FROM agent_memory WHERE key=?", (key,)
        ).fetchone()
    return row[0] if row else None


def remember(db: Path, key: str, value: str) -> str:
    validate_tool("remember", {"key": key, "value": value})
    _check_db(db)
    with sqlite3.connect(db) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "INSERT INTO agent_memory(key,value,updated_ms) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "updated_ms=excluded.updated_ms",
            (key, value, int(time.time() * 1000)),
        )
    return "saved"
