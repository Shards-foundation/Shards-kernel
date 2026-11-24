"""Single-host, loopback-only operator service with public-key permit verification.

No private signing key, dynamic plugin, remote bind, wallet or unsigned execution
is available through this entrypoint. This is NOT a production deployment.
"""

from __future__ import annotations

import hmac
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from implementations.storage import SQLiteAuditStorage
from shards_kernel.common.time import PersistentSystemClock, SystemClock
from shards_kernel.common.types import KernelConfig
from shards_kernel.integrations.auth import AgentIdentity, resolve_api_key
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PublicVerificationKey
from shards_kernel.providers.github_issue_label import (
    TOOL_NAME as GITHUB_LABEL_TOOL,
)
from shards_kernel.providers.github_issue_label import (
    EnvTokenSupplier,
    GitHubIssueLabelConfig,
    GitHubIssueLabelProvider,
    HttpTransport,
    ProviderError,
)
from shards_kernel.providers.journal import ProviderEffectJournal
from shards_kernel.sdk.server import KernelServer
from shards_kernel.variants.strict_kernel import StrictKernel

_ALLOWED_TOOLS = frozenset({"echo", "add"})
_BUILTIN_TOOLS = _ALLOWED_TOOLS  # v1/v2 remain builtin-only.
_PROVIDER_TOOLS = frozenset({GITHUB_LABEL_TOOL})
_RESERVED_SECRET_ENVS = frozenset(
    {
        "SHARDS_KERNEL_API_KEY",
        "SHARDS_KERNEL_AGENT_AUTH_PEPPER",
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
    }
)
_PROVIDER_SECRET_ENV_PREFIX = "SHARDS_KERNEL_GITHUB_"
_GATEWAY_SECRET_ENV_PREFIX = "SHARDS_KERNEL_GATEWAY_"
_MAX_CONFIG_BYTES = 64 * 1024


@dataclass(frozen=True)
class GitHubProviderConfig:
    """Operator-pinned GitHub label scope. No credential value is stored."""

    owner: str
    repo: str
    allowed_labels: tuple[str, ...]
    max_issue_number: int
    journal_db: Path
    token_env: str


@dataclass(frozen=True)
class GatewayConfig:
    """Explicit reverse-proxy/tunnel identity presented to the loopback service."""

    identity: str
    token_env: str


@dataclass(frozen=True)
class OperatorServiceConfig:
    """Validated immutable operator input, never including credentials."""

    kernel_id: str
    actor: str | None
    tools: tuple[str, ...]
    public_keys: dict[str, PublicVerificationKey]
    audit_db: Path
    port: int
    version: int = 1
    agents: tuple[AgentIdentity, ...] = ()
    provider: GitHubProviderConfig | None = None
    gateway: GatewayConfig | None = None


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


def _validated_tools(value: Any, allowed: frozenset[str] = _ALLOWED_TOOLS) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(t, str) or t not in allowed for t in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(
            "tools must be a unique, nonempty allowlist drawn from: "
            + ", ".join(sorted(allowed))
        )
    return value


def _github_name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= 100)
        or not value.isascii()
        or not all(c.isalnum() or c in "-_." for c in value)
        or value in {".", ".."}
    ):
        raise ValueError(label + " must be a concrete GitHub owner/repository name")
    return value


def _label_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or value != value.strip()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError("allowed_labels must contain bounded printable label names")
    return value


def _secret_env(value: Any, label: str, *, role: str) -> str:
    if (
        not isinstance(value, str)
        or not (3 <= len(value) <= 64)
        or not value.isascii()
        or not (value[0].isupper() or value[0] == "_")
        or not all(c.isupper() or c.isdigit() or c == "_" for c in value)
    ):
        raise ValueError(label + " must name an uppercase environment variable")
    if value in _RESERVED_SECRET_ENVS:
        raise ValueError(label + " must not reuse another operator credential")
    required_prefix = (
        _PROVIDER_SECRET_ENV_PREFIX if role == "provider"
        else _GATEWAY_SECRET_ENV_PREFIX
    )
    if not value.startswith(required_prefix):
        raise ValueError(label + " must use its role-specific secret namespace")
    return value


def _parse_github_provider(value: Any) -> GitHubProviderConfig:
    provider = _fields(
        value,
        {
            "kind",
            "owner",
            "repo",
            "allowed_labels",
            "max_issue_number",
            "journal_db",
            "token_env",
        },
        "GitHub provider",
    )
    if provider["kind"] != "github_issue_label":
        raise ValueError("Unsupported provider kind")
    owner = _github_name(provider["owner"], "provider owner")
    repo = _github_name(provider["repo"], "provider repo")
    labels = provider["allowed_labels"]
    if (
        not isinstance(labels, list)
        or not (1 <= len(labels) <= 32)
        or len(set(labels)) != len(labels)
    ):
        raise ValueError("allowed_labels must be a unique nonempty list of at most 32 labels")
    allowed_labels = tuple(_label_name(label) for label in labels)
    maximum = provider["max_issue_number"]
    if type(maximum) is not int or not 1 <= maximum <= 10_000_000:
        raise ValueError("max_issue_number must be an integer between 1 and 10000000")
    journal_db = _database_path(provider["journal_db"], "provider journal_db")
    token_env = _secret_env(
        provider["token_env"], "provider token_env", role="provider"
    )
    return GitHubProviderConfig(
        owner=owner,
        repo=repo,
        allowed_labels=allowed_labels,
        max_issue_number=maximum,
        journal_db=journal_db,
        token_env=token_env,
    )


def _parse_gateway(value: Any) -> GatewayConfig:
    gateway = _fields(value, {"identity", "token_env"}, "Gateway")
    identity = _identifier(gateway["identity"], "gateway identity")
    token_env = _secret_env(
        gateway["token_env"], "gateway token_env", role="gateway"
    )
    return GatewayConfig(identity=identity, token_env=token_env)


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


def _database_path(value: Any, label: str = "audit_db") -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(label + " must be an absolute filesystem path")
    database = Path(value)
    if not database.is_absolute() or database.name in {"", ".", ".."}:
        raise ValueError(label + " must be an absolute filesystem path")
    if not database.parent.is_dir() or database.is_symlink() or database.is_dir():
        raise ValueError(label + " parent must exist; symlinks and directories are refused")
    return database


def _audit_path(value: Any) -> Path:
    return _database_path(value, "audit_db")


def _service_port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return value


def _parse_agent_identities(
    raw: Any,
    configured_tools: list[str],
    allowed: frozenset[str] = _ALLOWED_TOOLS,
) -> tuple[AgentIdentity, ...]:
    """Validate independently enrolled agents; no tokens or private keys in JSON."""
    if not isinstance(raw, list) or not 2 <= len(raw) <= 16:
        raise ValueError("v2 requires between two and sixteen independently enrolled agents")
    actors: set[str] = set()
    digests: set[str] = set()
    identities: list[AgentIdentity] = []
    for row in raw:
        item = _fields(
            row, {"actor", "token_scrypt", "allowed_tools"}, "Agent identity"
        )
        actor = _identifier(item["actor"], "agent actor")
        if "." in actor:
            raise ValueError("Multi-agent actor labels cannot contain the token separator")
        digest = item["token_scrypt"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("agent token_scrypt must be exactly 64 lowercase hex characters")
        if actor in actors or digest in digests:
            raise ValueError("Agent actors and memory-hard credential verifiers must be unique")
        agent_tools = _validated_tools(item["allowed_tools"], allowed)
        if not set(agent_tools).issubset(configured_tools):
            raise ValueError("Agent tool scope cannot exceed configured tool allowlist")
        actors.add(actor)
        digests.add(digest)
        identities.append(
            AgentIdentity(actor=actor, token_scrypt=digest, allowed_tools=frozenset(agent_tools))
        )
    return tuple(identities)


def parse_operator_config(data: Any) -> OperatorServiceConfig:
    """Validate v1/v2 builtin or v3 provider operator schema.

    v1/v2 keep the original echo/add-only surface. v3 is an explicit opt-in
    profile that additionally allows the single allowlisted GitHub label
    provider and an optional gateway identity. No schema accepts a credential
    value; only the *name* of an operator-managed environment variable.
    """
    if not isinstance(data, dict) or type(data.get("version")) is not int:
        raise ValueError("Operator version must be an integer")
    version = data["version"]
    common = {"version", "kernel_id", "tools", "issuer_keys", "audit_db", "port"}
    provider = None
    gateway = None
    if version == 1:
        data = _fields(data, common | {"actor"}, "Operator v1")
        allowed_tools = _ALLOWED_TOOLS
    elif version == 2:
        data = _fields(data, common | {"agents"}, "Operator v2")
        allowed_tools = _ALLOWED_TOOLS
    elif version == 3:
        data = _fields(
            data, common | {"agents", "provider", "gateway"}, "Operator v3"
        )
        allowed_tools = _BUILTIN_TOOLS | _PROVIDER_TOOLS
        provider = _parse_github_provider(data["provider"])
        gateway = _parse_gateway(data["gateway"])
        if gateway.token_env == provider.token_env:
            raise ValueError("Gateway and provider credentials must be separate")
    else:
        raise ValueError("Unsupported operator configuration version")

    kernel_id = _identifier(data["kernel_id"], "kernel_id")
    raw_tools = _validated_tools(data["tools"], allowed_tools)
    if version == 3:
        if provider is None or GITHUB_LABEL_TOOL not in raw_tools:
            raise ValueError("Operator v3 must enable the configured provider tool")
    elif any(tool in _PROVIDER_TOOLS for tool in raw_tools):
        raise ValueError("Provider tools require the explicit v3 profile")
    keys = _parse_public_keys(data["issuer_keys"], kernel_id)
    audit_db = _audit_path(data["audit_db"])
    port = _service_port(data["port"])
    actor = _identifier(data["actor"], "actor") if version == 1 else None
    agents = (
        _parse_agent_identities(data["agents"], raw_tools, allowed_tools)
        if version >= 2
        else ()
    )
    return OperatorServiceConfig(
        kernel_id=kernel_id,
        actor=actor,
        tools=tuple(raw_tools),
        public_keys=keys,
        audit_db=audit_db,
        port=port,
        version=version,
        agents=agents,
        provider=provider,
        gateway=gateway,
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
    agent_pepper: str | None = None,
    policy_expires_at_ms: int | None = None,
    github_transport: HttpTransport | None = None,
    audit_storage: Any | None = None,
) -> KernelServer:
    """Create a service kernel; no arbitrary tools or HMAC private secrets.

    ``github_transport`` exists so tests can route the provider's exact
    production request path to a real local HTTP test server. It cannot change
    the pinned ``https://api.github.com`` base or the allowlisted scope.
    """
    if config.provider is not None and config.gateway is None:
        raise ValueError("Provider profile requires a gateway identity")
    key = resolve_api_key(api_key)
    storage = (
        audit_storage
        if audit_storage is not None
        else SQLiteAuditStorage(str(config.audit_db))
    )
    kernel = StrictKernel(audit_storage=storage)
    kernel.boot(
        KernelConfig(
            kernel_id=config.kernel_id,
            variant="strict",
            clock=PersistentSystemClock(str(config.audit_db), config.kernel_id),
        )
    )
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset(a.actor for a in config.agents)
            if config.version >= 2 else frozenset({config.actor}),
            allowed_tools=frozenset(config.tools),
        )
    )
    kernel.set_public_verifiers(config.public_keys)

    provider = None
    provider_journal = None
    if config.provider is not None:
        provider_config = GitHubIssueLabelConfig(
            owner=config.provider.owner,
            repo=config.provider.repo,
            allowed_labels=frozenset(config.provider.allowed_labels),
            max_issue_number=config.provider.max_issue_number,
            token_env=config.provider.token_env,
        )
        # Fail startup closed if the operator-managed credential is absent or
        # malformed. The value is never stored on the provider or returned.
        token_supplier = EnvTokenSupplier(config.provider.token_env)
        try:
            token_supplier()
        except ProviderError:
            raise ValueError("GitHub provider credential is unavailable or invalid") from None
        provider_journal = ProviderEffectJournal(str(config.provider.journal_db))
        provider = GitHubIssueLabelProvider(
            config=provider_config,
            journal=provider_journal,
            token_supplier=token_supplier,
            transport=github_transport,
        )
        kernel.register_tool(
            name=GITHUB_LABEL_TOOL,
            handler=provider.handle_issue_add_label,
            description="Add one allowlisted label to a pre-existing GitHub issue",
            param_schema={"issue_number": int, "label": str},
        )

    gateway_identity = None
    gateway_token = None
    if config.gateway is not None:
        gateway_token = os.environ.get(config.gateway.token_env)
        if (
            not isinstance(gateway_token, str)
            or len(gateway_token) < 32
            or gateway_token != gateway_token.strip()
        ):
            raise ValueError("Gateway credential is unavailable or too weak")
        if config.provider is not None and hmac.compare_digest(
            gateway_token, os.environ.get(config.provider.token_env, "")
        ):
            raise ValueError("Gateway and provider credentials must be separate")
        gateway_identity = config.gateway.identity

    server = KernelServer(
        kernel,
        host="127.0.0.1",
        port=config.port,
        api_key=key,
        trusted_actor=config.actor,
        agent_identities=config.agents,
        agent_auth_pepper=agent_pepper,
        policy_expires_at_ms=policy_expires_at_ms,
        gateway_identity=gateway_identity,
        gateway_token=gateway_token,
    )
    server.provider = provider
    server.provider_journal = provider_journal
    return server



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
