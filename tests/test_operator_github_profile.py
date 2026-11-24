"""Operator v3 E2E: signed v2 permit -> real kernel -> local HTTP provider.

The provider is a real loopback HTTP server. The kernel is the real strict
kernel with its real SQLite audit ledger and nonce replay state. Only the
provider transport target is local; the request path and allowlists are the
production ones.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from implementations.storage import SQLiteAuditStorage
from shards_kernel.cli.service import build_operator_server, parse_operator_config
from shards_kernel.cli.signed_policy import verify_signed_policy
from shards_kernel.integrations.auth import agent_token_kdf
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_operator_policy, sign_v2_permit
from shards_kernel.permits import PermitBuilder
from shards_kernel.providers.github_issue_label import TOOL_NAME
from shards_kernel.providers.journal import SUCCEEDED, UNKNOWN
from tests.github_issue_label_test_server import GitHubTestProvider, LoopbackTransport

KERNEL_ID = "github-operator"
GATEWAY_ID = "edge-gateway"
GITHUB_ENV = "SHARDS_KERNEL_GITHUB_TOKEN"
GATEWAY_ENV = "SHARDS_KERNEL_GATEWAY_TOKEN"


def _raw_config(tmp_path, issuer: Ed25519PrivateKey, alice_digest: str, bob_digest: str) -> dict:
    return {
        "version": 3,
        "kernel_id": KERNEL_ID,
        "tools": [TOOL_NAME],
        "agents": [
            {
                "actor": "agent-alice",
                "token_scrypt": alice_digest,
                "allowed_tools": [TOOL_NAME],
            },
            {
                "actor": "agent-bob",
                "token_scrypt": bob_digest,
                "allowed_tools": [TOOL_NAME],
            },
        ],
        "issuer_keys": [
            {
                "key_id": "issuer-key",
                "issuer": "operator",
                "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
                "revoked": False,
            }
        ],
        "audit_db": str(tmp_path / "audit.sqlite3"),
        "port": 8765,
        "provider": {
            "kind": "github_issue_label",
            "owner": "octo",
            "repo": "demo",
            "allowed_labels": ["triage"],
            "max_issue_number": 100,
            "journal_db": str(tmp_path / "journal.sqlite3"),
            "token_env": GITHUB_ENV,
        },
        "gateway": {"identity": GATEWAY_ID, "token_env": GATEWAY_ENV},
    }


@pytest.fixture
def stack(tmp_path, monkeypatch):
    provider = GitHubTestProvider().start()
    issuer = Ed25519PrivateKey.generate()
    alice_token = "agent-alice." + secrets.token_urlsafe(40)
    bob_token = "agent-bob." + secrets.token_urlsafe(40)
    pepper = secrets.token_urlsafe(48)
    admin = secrets.token_urlsafe(40)
    gateway = secrets.token_urlsafe(40)
    github_token = "ghp_" + secrets.token_urlsafe(30)
    monkeypatch.setenv(GITHUB_ENV, github_token)
    monkeypatch.setenv(GATEWAY_ENV, gateway)
    raw = _raw_config(
        tmp_path,
        issuer,
        agent_token_kdf(alice_token, pepper.encode()),
        agent_token_kdf(bob_token, pepper.encode()),
    )
    config = replace(parse_operator_config(raw), port=0)

    def build(**kwargs):
        return build_operator_server(
            config,
            api_key=admin,
            agent_pepper=pepper,
            github_transport=LoopbackTransport(provider.base_url),
            **kwargs,
        )

    server = build()
    server.start(blocking=False)
    base = "http://127.0.0.1:" + str(server._server.server_address[1])
    state = SimpleNamespace(
        provider=provider,
        issuer=issuer,
        alice_token=alice_token,
        bob_token=bob_token,
        pepper=pepper,
        admin=admin,
        gateway=gateway,
        github_token=github_token,
        raw=raw,
        config=config,
        build=build,
        server=server,
        base=base,
    )
    try:
        yield state
    finally:
        state.server.stop()
        provider.stop()


def _permit(
    issuer: Ed25519PrivateKey,
    actor: str,
    params: dict,
    *,
    action: str = TOOL_NAME,
    key_id: str = "issuer-key",
    audience: str = KERNEL_ID,
    valid_from: int | None = None,
    valid_until: int | None = None,
):
    now = int(time.time() * 1000)
    return sign_v2_permit(
        (
            PermitBuilder()
            .issuer("operator")
            .subject(actor)
            .jurisdiction("default")
            .action(action)
            .params(params)
            .constraints({})
            .max_executions(1)
            .valid_from_ms(now - 60_000 if valid_from is None else valid_from)
            .valid_until_ms(now + 120_000 if valid_until is None else valid_until)
            .proposal_hash("approved-" + actor)
            .build_unsigned_v2(key_id=key_id, audience=audience)
        ),
        issuer,
    )


def _payload(
    actor: str,
    params: dict,
    request_id: str,
    permit=None,
    *,
    action: str = TOOL_NAME,
) -> dict:
    body = {
        "request_id": request_id,
        "actor": actor,
        "intent": "add one allowlisted label",
        "tool_call": {"name": action, "params": params},
        "params": params,
    }
    if permit is not None:
        body["permit"] = permit_to_mapping(permit)
    return body


def _http(
    stack,
    path: str,
    *,
    method: str = "GET",
    data: dict | None = None,
    bearer: str | None = None,
    gateway: bool = True,
    extra_headers: dict | None = None,
):
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = urllib.request.Request(stack.base + path, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if bearer is not None:
        request.add_header("Authorization", "Bearer " + bearer)
    if gateway:
        request.add_header("X-Shards-Gateway-Identity", GATEWAY_ID)
        request.add_header("X-Shards-Gateway-Token", stack.gateway)
    for key, value in (extra_headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310: loopback test URL
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _submit(
    stack,
    body: dict,
    *,
    bearer: str,
    gateway: bool = True,
    extra_headers: dict | None = None,
):
    return _http(
        stack,
        "/submit",
        method="POST",
        data=body,
        bearer=bearer,
        gateway=gateway,
        extra_headers=extra_headers,
    )


def test_v3_config_is_explicit_and_contains_no_credentials(tmp_path, stack):
    config = stack.config
    assert config.version == 3
    assert config.tools == (TOOL_NAME,)
    assert config.provider.owner == "octo"
    assert config.provider.allowed_labels == ("triage",)
    assert config.gateway.identity == GATEWAY_ID
    assert stack.github_token not in json.dumps(stack.raw)
    assert stack.gateway not in json.dumps(stack.raw)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.update({"version": 2}),
        lambda raw: raw.update({"tools": ["echo"]}),
        lambda raw: raw["provider"].update({"kind": "shell"}),
        lambda raw: raw["provider"].update({"owner": "../escape"}),
        lambda raw: raw["provider"].update({"allowed_labels": []}),
        lambda raw: raw["provider"].update({"max_issue_number": True}),
        lambda raw: raw["provider"].update({"journal_db": "relative.sqlite3"}),
        lambda raw: raw["provider"].update({"token_env": "SHARDS_KERNEL_API_KEY"}),
        lambda raw: raw["gateway"].update({"token_env": GITHUB_ENV}),
        lambda raw: raw.update({"unexpected": True}),
    ],
)
def test_v3_config_rejects_unsafe_or_ambiguous_profiles(tmp_path, stack, mutate):
    raw = json.loads(json.dumps(stack.raw))
    mutate(raw)
    with pytest.raises(ValueError):
        parse_operator_config(raw)


def test_v3_requires_explicit_gateway_identity(tmp_path, stack):
    raw = json.loads(json.dumps(stack.raw))
    raw.pop("gateway")
    with pytest.raises(ValueError, match="Operator v3"):
        parse_operator_config(raw)


@pytest.mark.parametrize(
    "section, token_env",
    [
        ("provider", "SHARDS_KERNEL_GATEWAY_TOKEN"),
        ("gateway", "SHARDS_KERNEL_GITHUB_TOKEN"),
        ("provider", "SHARDS_KERNEL_TEST_GITHUB_TOKEN"),
        ("gateway", "SHARDS_KERNEL_TEST_GATEWAY_TOKEN"),
        ("provider", "SHARDS_KERNEL_AGENT_AUTH_PEPPER"),
    ],
)
def test_secret_names_are_role_isolated(stack, section, token_env):
    raw = json.loads(json.dumps(stack.raw))
    raw[section]["token_env"] = token_env
    with pytest.raises(ValueError, match="role-specific secret namespace|reuse"):
        parse_operator_config(raw)


def test_v3_signed_policy_envelope_verifies_and_rejects_tampering(tmp_path, stack):
    policy_key = Ed25519PrivateKey.generate()
    now = int(time.time() * 1000)
    envelope = sign_operator_policy(
        stack.raw,
        policy_key,
        revision=1,
        issued_at_ms=now,
        expires_at_ms=now + 3_600_000,
    )
    verified = verify_signed_policy(
        envelope,
        trusted_public_key_hex=policy_key.public_key().public_bytes_raw().hex(),
        current_time_ms=now + 1,
    )
    assert verified.config.version == 3
    assert verified.config.provider.owner == "octo"

    tampered = json.loads(json.dumps(envelope))
    tampered["config"]["provider"]["owner"] = "attacker"
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_signed_policy(
            tampered,
            trusted_public_key_hex=policy_key.public_key().public_bytes_raw().hex(),
            current_time_ms=now + 1,
        )


def test_valid_signed_permit_adds_label_and_writes_audit(tmp_path, stack):
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    status, body = _submit(
        stack, _payload("agent-alice", params, "req-1", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert body["status"] == "ACCEPTED"
    assert body["decision"] == "ALLOW"
    assert body["result"]["state"] == "SUCCEEDED"
    assert body["result"]["already_present"] is False
    assert stack.provider.post_count == 1
    assert stack.provider.labels[7] == {"triage"}

    journal = stack.server.provider_journal
    record = journal.get(body["result"]["operation_id"])
    assert record.state == SUCCEEDED
    assert record.request_id == "req-1"
    assert record.permit_id == permit.permit_id

    entries = stack.server.kernel.export_evidence().ledger_entries
    assert len(entries) >= 2
    assert entries[0].audit_phase == "intent"
    assert entries[0].permit_digest == permit.permit_id
    assert entries[-1].audit_phase == "outcome"
    assert entries[-1].permit_digest == permit.permit_id
    assert stack.github_token not in json.dumps(body)


def test_actor_and_credential_confusion_is_refused(tmp_path, stack):
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    body = _payload("agent-alice", params, "req-1", permit)

    # Agent cannot claim another actor.
    status, _ = _submit(stack, {**body, "actor": "agent-bob"}, bearer=stack.alice_token)
    assert status == 403
    # Another agent's credential cannot submit for alice.
    status, _ = _submit(stack, body, bearer=stack.bob_token)
    assert status == 403
    # The operator credential is not an agent credential.
    status, _ = _submit(stack, body, bearer=stack.admin)
    assert status == 401
    # Missing credential.
    status, _ = _http(stack, "/submit", method="POST", data=body, bearer=None)
    assert status == 401
    assert stack.provider.post_count == 0


def test_forged_expired_and_replayed_permits_have_no_effect(tmp_path, stack):
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}

    attacker = Ed25519PrivateKey.generate()
    forged = _permit(attacker, "agent-alice", params)
    status, body = _submit(
        stack, _payload("agent-alice", params, "forged", forged), bearer=stack.alice_token
    )
    assert status == 200
    assert body["decision"] == "DENY"
    assert "SIGNATURE_INVALID" in body["error"]
    assert stack.provider.post_count == 0

    now = int(time.time() * 1000)
    expired = _permit(
        stack.issuer, "agent-alice", params, valid_from=now - 120_000, valid_until=now - 60_000
    )
    status, body = _submit(
        stack, _payload("agent-alice", params, "expired", expired), bearer=stack.alice_token
    )
    assert status == 200
    assert body["decision"] == "DENY"
    assert "EXPIRED" in body["error"]
    assert stack.provider.post_count == 0

    valid = _permit(stack.issuer, "agent-alice", params)
    status, first = _submit(
        stack, _payload("agent-alice", params, "replay-1", valid), bearer=stack.alice_token
    )
    assert status == 200 and first["decision"] == "ALLOW"
    assert stack.provider.post_count == 1
    status, second = _submit(
        stack, _payload("agent-alice", params, "replay-2", valid), bearer=stack.alice_token
    )
    assert status == 200
    assert second["decision"] == "DENY"
    assert "REPLAY_DETECTED" in second["error"]
    assert stack.provider.post_count == 1


def test_params_mismatch_allowlist_and_bounds_fail_closed(tmp_path, stack):
    stack.provider.add_issue(7)
    stack.provider.add_issue(8)

    signed = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", signed)
    status, body = _submit(
        stack,
        _payload("agent-alice", {"issue_number": 8, "label": "triage"}, "mismatch", permit),
        bearer=stack.alice_token,
    )
    assert status == 200
    assert body["decision"] == "DENY"
    assert "PARAMS_MISMATCH" in body["error"]
    assert stack.provider.post_count == 0

    forbidden = {"issue_number": 7, "label": "forbidden"}
    permit = _permit(stack.issuer, "agent-alice", forbidden)
    status, body = _submit(
        stack, _payload("agent-alice", forbidden, "label", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert body["status"] == "FAILED"
    assert "LABEL_NOT_ALLOWED" in body["error"]
    assert stack.provider.post_count == 0

    oversized = {"issue_number": 101, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", oversized)
    status, body = _submit(
        stack, _payload("agent-alice", oversized, "bounds", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert body["status"] == "FAILED"
    assert "INVALID_ISSUE_NUMBER" in body["error"]
    assert stack.provider.post_count == 0

    extra = {"issue_number": 7, "label": "triage", "url": "https://attacker.example"}
    permit = _permit(stack.issuer, "agent-alice", extra)
    status, body = _submit(
        stack, _payload("agent-alice", extra, "extra", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert body["decision"] == "DENY"
    assert "PARAM_BINDING_MISMATCH" in body["error"]
    assert stack.provider.post_count == 0


def test_gateway_identity_is_required_and_spoofed_headers_are_refused(tmp_path, stack):
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    body = _payload("agent-alice", params, "gateway", permit)

    status, _ = _submit(stack, body, bearer=stack.alice_token, gateway=False)
    assert status == 401
    status, _ = _submit(
        stack, body, bearer=stack.alice_token, extra_headers={"X-Shards-Gateway-Token": "wrong"}
    )
    assert status == 401
    status, _ = _submit(
        stack, body, bearer=stack.alice_token, extra_headers={"X-Shards-Gateway-Identity": "other"}
    )
    assert status == 403
    status, _ = _submit(
        stack, body, bearer=stack.alice_token, extra_headers={"X-Actor": "agent-alice"}
    )
    assert status == 403
    status, _ = _submit(
        stack, body, bearer=stack.alice_token, extra_headers={"X-Forwarded-User": "agent-alice"}
    )
    assert status == 403
    assert stack.provider.post_count == 0

    status, result = _submit(stack, body, bearer=stack.alice_token)
    assert status == 200 and result["decision"] == "ALLOW"
    assert stack.provider.post_count == 1

    status, _ = _http(stack, "/status", bearer=stack.admin, gateway=False)
    assert status == 401
    status, _ = _http(stack, "/status", bearer=stack.admin)
    assert status == 200
    status, health = _http(stack, "/health", gateway=False)
    assert status == 200 and health["status"] == "healthy"


def test_ambiguous_github_error_is_quarantined_and_not_retried(tmp_path, stack):
    stack.provider.add_issue(7)
    stack.provider.post_status = 403
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    status, body = _submit(
        stack, _payload("agent-alice", params, "unknown", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert body["status"] == "FAILED"
    assert body["decision"] == "DENY"
    assert "PROVIDER_EFFECT_UNKNOWN" in body["error"]
    assert stack.provider.post_count == 1
    open_operations = stack.server.provider_journal.open_operations()
    assert len(open_operations) == 1
    assert open_operations[0].state == UNKNOWN

    # Replaying the same signed permit is denied before any provider call.
    status, replay = _submit(
        stack, _payload("agent-alice", params, "unknown-2", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert "REPLAY_DETECTED" in replay["error"]
    assert stack.provider.post_count == 1


def test_restart_preserves_replay_state_and_idempotency(tmp_path, stack):
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    status, first = _submit(
        stack, _payload("agent-alice", params, "restart-1", permit), bearer=stack.alice_token
    )
    assert status == 200 and first["decision"] == "ALLOW"
    assert stack.provider.post_count == 1

    stack.server.stop()
    stack.server = stack.build()
    stack.server.start(blocking=False)
    stack.base = "http://127.0.0.1:" + str(stack.server._server.server_address[1])

    status, replay = _submit(
        stack, _payload("agent-alice", params, "restart-2", permit), bearer=stack.alice_token
    )
    assert status == 200
    assert replay["decision"] == "DENY"
    assert "REPLAY_DETECTED" in replay["error"]
    assert stack.provider.post_count == 1

    fresh = _permit(stack.issuer, "agent-alice", params)
    status, second = _submit(
        stack, _payload("agent-alice", params, "restart-3", fresh), bearer=stack.alice_token
    )
    assert status == 200
    assert second["decision"] == "ALLOW"
    assert second["result"]["already_present"] is True
    assert stack.provider.post_count == 1


class _FailingAuditStorage(SQLiteAuditStorage):
    """A real storage adapter whose durable append fails."""

    def append(self, kernel_id, entry):
        raise RuntimeError("simulated durable audit failure")


def test_audit_failure_prevents_dispatch(tmp_path, stack):
    stack.server.stop()
    stack.server = stack.build(
        audit_storage=_FailingAuditStorage(str(stack.config.audit_db))
    )
    stack.server.start(blocking=False)
    stack.base = "http://127.0.0.1:" + str(stack.server._server.server_address[1])
    stack.provider.add_issue(7)
    params = {"issue_number": 7, "label": "triage"}
    permit = _permit(stack.issuer, "agent-alice", params)
    status, _ = _submit(
        stack, _payload("agent-alice", params, "audit", permit), bearer=stack.alice_token
    )
    assert status == 500
    assert stack.provider.post_count == 0
    assert stack.server.kernel.get_state().value == "HALTED"


def test_missing_provider_or_gateway_credentials_prevent_startup(tmp_path, stack, monkeypatch):
    monkeypatch.delenv(GITHUB_ENV, raising=False)
    with pytest.raises(ValueError):
        stack.build()
    monkeypatch.setenv(GITHUB_ENV, stack.github_token)
    monkeypatch.delenv(GATEWAY_ENV, raising=False)
    with pytest.raises(ValueError):
        stack.build()
