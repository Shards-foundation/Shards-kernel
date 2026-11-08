#!/usr/bin/env python3
"""Local Qwen3 -> Shards-kernel 0.1.3 operator-approved tools.

This is a same-UID Termux demonstration, NOT a hardened trust boundary.
The model is only asked to propose structured actions; it receives no signer.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
import urllib.request
import uuid
import hashlib
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from implementations.storage import SQLiteAuditStorage
from shards_kernel.api import (
    Decision, JurisdictionPolicy, KernelConfig, KernelRequest, PermitBuilder,
    StrictKernel, ToolCall, ReceiptStatus, replay_and_verify,
)
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.time import PersistentSystemClock
from shards_kernel.integrations.generic_adapter import GenericAdapter
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PublicVerificationKey

ROOT = Path.home() / ".shards-qwen3-v2"
KERNEL_ID = "termux-qwen3-v2"
ACTOR = "qwen3-local"
ISSUER = "termux-operator"
KEY_ID = "termux-operator-key-v2"
MODEL_HOST = "http://127.0.0.1:8080"
ALLOWED = frozenset({"add", "echo", "list_notes", "read_note", "remember", "recall"})
NOTE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.(?:md|txt|json)\Z")
KEY_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
MAX_ACTIONS = 3


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def init(root: Path) -> None:
    if root.is_symlink():
        raise ValueError("Root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Root must be a real directory")
    os.chmod(root, 0o700)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700, exist_ok=True)
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("Workspace must be a regular directory")
    key_file = root / "operator.key"
    pub_file = root / "operator.pub"
    if not key_file.exists() and not pub_file.exists():
        private = Ed25519PrivateKey.generate()
        secret = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        write_exclusive(key_file, secret, 0o600)
        write_exclusive(pub_file, pub, 0o600)
    if not key_file.is_file() or not pub_file.is_file():
        raise ValueError("Operator keypair incomplete; refusing implicit rotation")
    if key_file.is_symlink() or pub_file.is_symlink():
        raise ValueError("Operator keypair must not be symlinks")
    if stat.S_IMODE(key_file.stat().st_mode) != 0o600:
        raise ValueError("Operator signing key must be mode 0600")
    private = Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
    expected_pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if pub_file.read_bytes() != expected_pub:
        raise ValueError("Operator public key does not match private key")
    db = root / "audit.sqlite3"
    SQLiteAuditStorage(str(db))
    # Memory has a separate transaction boundary from the kernel audit.
    with sqlite3.connect(db) as con:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("CREATE TABLE IF NOT EXISTS agent_memory ("
                    "key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ms INTEGER NOT NULL)")
    print("INIT PASS:", root)


def validate(tool: Any, params: Any) -> tuple[str, dict[str, Any]]:
    if type(tool) is not str or tool not in ALLOWED or type(params) is not dict:
        raise ValueError("Unknown tool or malformed parameters")
    shapes = {"add": {"a", "b"}, "echo": {"text"},
              "list_notes": set(), "read_note": {"name"},
              "remember": {"key", "value"}, "recall": {"key"}}
    if set(params) != shapes[tool]:
        raise ValueError("Unexpected/missing tool parameters")
    if tool == "add":
        if any(type(params[k]) is not int or abs(params[k]) > 1_000_000 for k in ("a", "b")):
            raise ValueError("add requires bounded integer arguments")
    elif tool == "echo":
        if type(params["text"]) is not str or not 1 <= len(params["text"]) <= 200:
            raise ValueError("Invalid echo text")
    elif tool == "read_note":
        name = params["name"]
        if type(name) is not str or not NOTE_PATTERN.fullmatch(name) or ".." in name:
            raise ValueError("Invalid note name")
    elif tool in ("remember", "recall"):
        key = params["key"]
        if type(key) is not str or not KEY_PATTERN.fullmatch(key):
            raise ValueError("Invalid memory key")
        if tool == "remember":
            value = params["value"]
            if type(value) is not str or not 1 <= len(value) <= 500:
                raise ValueError("Invalid memory value")
    return tool, dict(params)


def parse_plan(data: str) -> list[tuple[str, dict[str, Any]]]:
    if type(data) is not str or len(data) > 10_000:
        raise ValueError("Malformed/oversized model output")
    payload = json.loads(data)
    if type(payload) is not dict or set(payload) != {"actions"}:
        raise ValueError("Expected exact actions object")
    actions = payload["actions"]
    if type(actions) is not list or len(actions) > MAX_ACTIONS:
        raise ValueError("Too many actions or malformed plan")
    parsed = []
    for action in actions:
        if type(action) is not dict or set(action) != {"tool", "params"}:
            raise ValueError("Malformed action object")
        parsed.append(validate(action["tool"], action["params"]))
    return parsed


def safe_read_note(workspace: Path, name: str) -> str:
    validate("read_note", {"name": name})
    # Open a fixed directory and a single filename. Refuse symlink traversal.
    dfd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > 8192:
                raise ValueError("Not a regular note or note is too large")
            content = os.read(fd, 8193)
            if len(content) > 8192:
                raise ValueError("Note exceeds 8 KiB")
            return content.decode("utf-8", errors="strict")
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def list_notes(workspace: Path) -> list[str]:
    names = []
    for entry in workspace.iterdir():
        name = entry.name
        if NOTE_PATTERN.fullmatch(name) and ".." not in name and not entry.is_symlink() and entry.is_file():
            names.append(name)
    return sorted(names)[:50]


def recall(db: Path, key: str) -> str | None:
    validate("recall", {"key": key})
    with sqlite3.connect(db) as con:
        row = con.execute("SELECT value FROM agent_memory WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def remember(db: Path, key: str, value: str) -> str:
    validate("remember", {"key": key, "value": value})
    with sqlite3.connect(db) as con:
        con.execute("PRAGMA synchronous=FULL")
        con.execute(
            "INSERT INTO agent_memory(key,value,updated_ms) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ms=excluded.updated_ms",
            (key, value, int(time.time() * 1000)),
        )
    return "saved"


def launch(root: Path):
    pub_file = root / "operator.pub"
    db = root / "audit.sqlite3"
    if not pub_file.is_file() or pub_file.is_symlink() or not db.is_file():
        raise ValueError("Run init first; public verifier or audit DB missing")
    storage = SQLiteAuditStorage(str(db))
    clock = PersistentSystemClock(str(db), KERNEL_ID)
    kernel = StrictKernel(audit_storage=storage)
    kernel.set_public_verifiers({
        KEY_ID: PublicVerificationKey(issuer=ISSUER, audience=KERNEL_ID, public_key=pub_file.read_bytes())
    })
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({ACTOR}), allowed_tools=ALLOWED,
        allow_intent_only=False,
    ))
    kernel.boot(KernelConfig(kernel_id=KERNEL_ID, variant="strict", clock=clock))
    # The official GenericAdapter registers explicitly permitted custom handlers.
    adapter = GenericAdapter(kernel, actor=ACTOR)
    adapter.register_tool("list_notes", lambda: list_notes(root / "workspace"))
    adapter.register_tool("read_note", lambda name: safe_read_note(root / "workspace", name))
    adapter.register_tool("remember", lambda key, value: remember(db, key, value))
    adapter.register_tool("recall", lambda key: recall(db, key))
    return kernel, clock


def issue(root: Path, clock, tool: str, params: dict[str, Any]):
    validate(tool, params)
    # Operator approval MUST have happened before calling this function.
    key_path = root / "operator.key"
    if key_path.is_symlink() or stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise ValueError("Insecure operator key file")
    private = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    now = clock.now_ms()
    digest = hashlib.sha256(json.dumps(
        {"tool": tool, "params": params}, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    unsigned = (
        PermitBuilder().issuer(ISSUER).subject(ACTOR).jurisdiction("default")
        .action(tool).params(params).constraints({}).max_executions(1)
        .valid_from_ms(now - 1_000).valid_until_ms(now + 60_000)
        .proposal_hash(digest).evidence_hash("")
        .build_unsigned_v2(key_id=KEY_ID, audience=KERNEL_ID)
    )
    return sign_v2_permit(unsigned, private)


def make_request(clock, tool: str, params: dict[str, Any]) -> KernelRequest:
    return KernelRequest(
        request_id=uuid.uuid4().hex, ts_ms=clock.now_ms(), actor=ACTOR,
        intent=f"Execute operator-reviewed {tool}",
        tool_call=ToolCall(name=tool, params=dict(params)), params=dict(params),
    )


def execute(root: Path, kernel, clock, tool: str, params: dict[str, Any], approved: bool):
    validate(tool, params)
    permit = issue(root, clock, tool, params) if approved else None
    receipt = kernel.submit(make_request(clock, tool, params), permit_token=permit)
    print("DECISION:", receipt.decision.value)
    print("RESULT:", json.dumps(receipt.tool_result, ensure_ascii=False))
    print("ERROR:", receipt.error)
    return receipt


def check_audit(kernel) -> bool:
    evidence = kernel.export_evidence()
    entries = [audit_entry_to_dict(x) for x in evidence.ledger_entries]
    ok, errors = replay_and_verify(entries, evidence.root_hash)
    print("AUDIT:", "PASS" if ok else "FAIL", "entries:", len(entries))
    print("ROOT:", evidence.root_hash)
    if errors:
        print("ERRORS:", errors)
    return bool(ok)


def ask_model(prompt: str) -> list[tuple[str, dict[str, Any]]]:
    with urllib.request.urlopen(MODEL_HOST + "/v1/models", timeout=10) as response:
        models = json.load(response)
    model = models["data"][0]["id"]
    instruction = (
        "You are a tool proposal engine, not an operator. /no_think "
        "Respond with JSON only: {\"actions\":[{\"tool\":\"add\",\"params\":{\"a\":2,\"b\":3}}]}. "
        "Allowed tools: add(a:int,b:int), echo(text:str), list_notes(), "
        "read_note(name:str), remember(key:str,value:str), recall(key:str). "
        "You may suggest zero to three actions. "
        "For unknown requests return {\"actions\":[]}. "
        "Read only note files from the approved workspace. "
        "Memory keys are lowercase letters, digits, underscore or hyphen; no secrets. "
        "Do not include reasoning or markdown."
    )
    body = json.dumps({
        "model": model, "stream": False, "temperature": 0, "max_tokens": 450,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": instruction},
                     {"role": "user", "content": prompt + " /no_think"}],
    }).encode()
    req = urllib.request.Request(MODEL_HOST + "/v1/chat/completions", body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as response:
        data = json.load(response)
    return parse_plan(data["choices"][0]["message"]["content"])


def review_plan(root: Path, plan: list[tuple[str, dict[str, Any]]]) -> None:
    if not plan:
        print("No permissible actions proposed.")
        return
    kernel, clock = launch(root)
    for idx, (tool, params) in enumerate(plan, 1):
        print(f"\nSTEP {idx}/{len(plan)}:", json.dumps({"tool": tool, "params": params}, ensure_ascii=False))
        consent = input("Type APPROVE for this step (anything else denies): ").strip() == "APPROVE"
        receipt = execute(root, kernel, clock, tool, params, consent)
        if (receipt.decision != Decision.ALLOW or receipt.status != ReceiptStatus.ACCEPTED
                or receipt.error is not None):
            print("PLAN HALTED; remaining actions not attempted.")
            break
    if not check_audit(kernel):
        raise RuntimeError("Audit verification failed")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="shards-v2-") as d:
        root = Path(d)
        init(root)
        k, c = launch(root)
        assert execute(root, k, c, "add", {"a": 17, "b": 25}, False).decision == Decision.DENY
        signed = issue(root, c, "add", {"a": 17, "b": 25})
        allowed = k.submit(make_request(c, "add", {"a": 17, "b": 25}), permit_token=signed)
        assert allowed.decision == Decision.ALLOW and allowed.tool_result == 42
        assert k.submit(make_request(c, "add", {"a": 17, "b": 25}), permit_token=signed).decision == Decision.DENY
        bad = issue(root, c, "add", {"a": 2, "b": 3})
        assert k.submit(make_request(c, "add", {"a": 100, "b": 200}), permit_token=bad).decision == Decision.DENY
        (root / "workspace" / "hello.md").write_text("hello local AI", encoding="utf-8")
        assert execute(root, k, c, "read_note", {"name": "hello.md"}, True).tool_result == "hello local AI"
        assert execute(root, k, c, "remember", {"key": "demo", "value": "secure"}, True).decision == Decision.ALLOW
        assert execute(root, k, c, "recall", {"key": "demo"}, True).tool_result == "secure"
        try:
            validate("read_note", {"name": "../operator.key"})
            raise AssertionError("Traversal was not denied")
        except ValueError:
            pass
        (root / "workspace" / "alias.md").symlink_to(root / "operator.key")
        try:
            safe_read_note(root / "workspace", "alias.md")
            raise AssertionError("Symlink was not denied")
        except OSError:
            pass
        assert check_audit(k)
        k2, c2 = launch(root)
        assert k2.submit(make_request(c2, "add", {"a": 17, "b": 25}), permit_token=signed).decision == Decision.DENY
        assert execute(root, k2, c2, "recall", {"key": "demo"}, True).tool_result == "secure"
        assert check_audit(k2)
    print("SELF-TEST PASS: permit, replay, memory, notes, persistence, audit")


def main() -> int:
    command = sys.argv[1:]
    if command == ["init"]:
        init(ROOT)
    elif command == ["self-test"]:
        self_test()
    elif command == ["audit"]:
        k, _ = launch(ROOT)
        if not check_audit(k):
            return 2
    elif len(command) >= 2 and command[0] == "ask":
        review_plan(ROOT, ask_model(" ".join(command[1:])))
    elif len(command) == 3 and command[0] == "run":
        tool, params = command[1], json.loads(command[2])
        review_plan(ROOT, [validate(tool, params)])
    else:
        print('Usage: python agent_v2.py init | self-test | audit | ask "..." | run TOOL \'{"key":"value"}\'')
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, RuntimeError, sqlite3.Error,
            urllib.error.URLError, AssertionError) as exc:
        print("FAIL CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(2)