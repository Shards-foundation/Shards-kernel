"""Single-host, loopback-only operator service with public-key permit verification.

No private signing key, dynamic plugin, remote bind, wallet or unsigned execution
is available through this entrypoint. This is NOT a production deployment.
"""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from implementations.storage import SQLiteAuditStorage
from shards_kernel.common.time import SystemClock
from shards_kernel.common.types import KernelConfig
from shards_kernel.integrations.auth import resolve_api_key
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PublicVerificationKey
from shards_kernel.sdk.server import KernelServer
from shards_kernel.variants.strict_kernel import StrictKernel

_ALLOWED_TOOLS = frozenset({"echo", "add"})
_MAX_CONFIG_BYTES = 64 * 1024


@dataclass(frozen=True)
class OperatorServiceConfig:
    """Validated immutable operator input, never including credentials."""

    kernel_id: str
    actor: str
    tools: tuple[str, ...]
    public_keys: dict[str, PublicVerificationKey]
    audit_db: Path
    port: int
    version: int = 1


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON configuration field")
        output[key] = value
    return output


def _reject_constant(_value: str) -> None:
    raise ValueError("Non-finite numeric values are not allowed")


def _fields(data: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError(context + " fields do not match the supported schema")
    return data


def _identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= 128)
        or not value.isascii()
        or not all(c.isalnum() or c in "-_." for c in value)
        or value in {".", ".."}
    ):
        raise ValueError(label + " must be a restricted, nonempty identifier")
    return value


def _validated_tools(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(t, str) or t not in _ALLOWED_TOOLS for t in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError("tools must be a unique, nonempty allowlist of echo/add")
    return value


def _parse_public_keys(value: Any, kernel_id: str) -> dict[str, PublicVerificationKey]:
    """Pin key identity, issuer and intended kernel without any signing secrets."""
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ValueError("issuer_keys must be a nonempty list of at most 16 public keys")
    keys: dict[str, PublicVerificationKey] = {}
    for item in value:
        key = _fields(item, {"key_id", "issuer", "public_key_hex", "revoked"}, "Issuer key")
        key_id = _identifier(key["key_id"], "key_id")
        issuer = _identifier(key["issuer"], "issuer")
        if key_id in keys:
            raise ValueError("Duplicate key_id")
        hex_string = key["public_key_hex"]
        if (
            not isinstance(hex_string, str)
            or len(hex_string) != 64
            or any(c not in "0123456789abcdef" for c in hex_string)
        ):
            raise ValueError("public_key_hex must contain exactly 64 lowercase hex characters")
        if type(key["revoked"]) is not bool:
            raise ValueError("revoked must be a boolean")
        keys[key_id] = PublicVerificationKey(
            issuer=issuer,
            audience=kernel_id,
            public_key=bytes.fromhex(hex_string),
            revoked=key["revoked"],
        )
    if all(record.revoked for record in keys.values()):
        raise ValueError("At least one public issuer key must be active")
    return keys


def _audit_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("audit_db must be an absolute filesystem path")
    audit_db = Path(value)
    if not audit_db.is_absolute() or audit_db.name in {"", ".", ".."}:
        raise ValueError("audit_db must be an absolute filesystem path")
    if not audit_db.parent.is_dir() or audit_db.is_symlink() or audit_db.is_dir():
        raise ValueError("audit_db parent must exist; symlinks and directories are refused")
    return audit_db


def _service_port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return value


def parse_operator_config(data: Any) -> OperatorServiceConfig:
    """Validate exact v1 schema without ever interpreting code or secrets."""
    data = _fields(
        data,
        {"version", "kernel_id", "actor", "tools", "issuer_keys", "audit_db", "port"},
        "Operator",
    )
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Unsupported operator configuration version")
    kernel_id = _identifier(data["kernel_id"], "kernel_id")
    actor = _identifier(data["actor"], "actor")

    raw_tools = _validated_tools(data["tools"])
    keys = _parse_public_keys(data["issuer_keys"], kernel_id)
    audit_db = _audit_path(data["audit_db"])
    port = _service_port(data["port"])

    return OperatorServiceConfig(
        kernel_id=kernel_id,
        actor=actor,
        tools=tuple(raw_tools),
        public_keys=keys,
        audit_db=audit_db,
        port=port,
    )


def load_operator_config(path: str) -> OperatorServiceConfig:
    """Read a bounded UTF-8 JSON file with duplicate-key and NaN rejection."""
    config_path = Path(path)
    if not config_path.is_file() or config_path.is_symlink():
        raise ValueError("Configuration must be an existing non-symlink regular file")
    if config_path.stat().st_size > _MAX_CONFIG_BYTES:
        raise ValueError("Configuration file is too large")
    with config_path.open("rb") as stream:
        data = stream.read(_MAX_CONFIG_BYTES + 1)
    if len(data) > _MAX_CONFIG_BYTES:
        raise ValueError("Configuration file is too large")
    try:
        decoded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON configuration") from exc
    return parse_operator_config(decoded)


@contextmanager
def exclusive_local_audit_lock(audit_db: Path) -> Iterator[None]:
    """Block a second local service writer; no distributed/NFS guarantee.

    Exclusivity uses OS advisory locking and is held for the full service
    lifetime. Fail closed on unsupported platforms or lock contention.
    """
    try:
        import fcntl
    except ImportError as exc:
        raise RuntimeError("Local single-writer locking is unsupported on this host") from exc

    lock_path = audit_db.with_name(audit_db.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Audit lock must be a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def build_operator_server(
    config: OperatorServiceConfig, *, api_key: str | None = None,
    policy_expires_at_ms: int | None = None,
) -> KernelServer:
    """Create a service kernel; no arbitrary tools or HMAC private secrets."""
    key = resolve_api_key(api_key)
    storage = SQLiteAuditStorage(str(config.audit_db))
    kernel = StrictKernel(audit_storage=storage)
    kernel.boot(
        KernelConfig(
            kernel_id=config.kernel_id,
            variant="strict",
            clock=SystemClock(),
        )
    )
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({config.actor}),
            allowed_tools=frozenset(config.tools),
        )
    )
    kernel.set_public_verifiers(config.public_keys)
    return KernelServer(
        kernel,
        host="127.0.0.1",
        port=config.port,
        api_key=key,
        trusted_actor=config.actor,
        policy_expires_at_ms=policy_expires_at_ms,
    )


def run_service(config_path: str, *, allow_unsigned_local: bool = False) -> int:
    """Run a signed policy by default; unsigned is an explicit local-only opt-in."""
    try:
        if allow_unsigned_local:
            config = load_operator_config(config_path)
            signed = None
        else:
            from shards_kernel.cli.signed_policy import load_signed_policy
            # Trust root comes from the operator environment, NEVER from the
            # signed document itself. The service has no signing private key.
            trusted_key = os.environ.get("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX", "")
            signed = load_signed_policy(
                config_path, trusted_public_key_hex=trusted_key,
                current_time_ms=SystemClock().now_ms(),
            )
            config = signed.config
        with exclusive_local_audit_lock(config.audit_db):
            server = build_operator_server(
                config,
                policy_expires_at_ms=signed.expires_at_ms if signed else None,
            )
            if signed is not None:
                from shards_kernel.cli.signed_policy import checkpoint_signed_policy

                checkpoint_signed_policy(signed)
            print(
                "Operator service: LOCAL LOOPBACK ONLY; NOT production-ready"
                + (" (UNSIGNED LOCAL DEVELOPMENT)" if allow_unsigned_local else " (SIGNED POLICY)")
            )
            try:
                server.start(blocking=True)
            except KeyboardInterrupt:
                print("Operator service stopping")
            finally:
                server.stop()
        return 0
    except Exception:
        # Never leak private key material, paths, or bearer values into stdout.
        print("Operator service refused startup or failed; inspect local diagnostic logs")
        return 2
