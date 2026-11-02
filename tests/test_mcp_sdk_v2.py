"""MCP SDK v2 interoperability using the official in-memory client."""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp")
from mcp import Client  # noqa: E402

from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.integrations.mcp_sdk_v2 import create_official_mcp_server
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitBuilder
from shards_kernel.variants.strict_kernel import StrictKernel


KEYRING = {"test": b"local-test-key-for-mcp-v2-32-bytes!"}


def kernel_with_explicit_policy():
    kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id="mcp-v2-test", variant="strict", clock=VirtualClock(1000)))
    kernel.set_keyring(KEYRING)
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}),
            allowed_tools=frozenset({"repeat"}),
        )
    )
    return kernel


def permit_for(params, subject="alice"):
    return (
        PermitBuilder()
        .issuer("operator")
        .subject(subject)
        .jurisdiction("default")
        .action("repeat")
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("proof")
        .proposal_hash("approved")
        .build(KEYRING, "test")
    )


def test_official_client_discovery_permit_execution_and_replay_denial():
    called = []
    kernel = kernel_with_explicit_policy()
    server = create_official_mcp_server(
        kernel,
        actor="alice",
        handlers={"repeat": lambda text: called.append(text) or text},
    )

    async def scenario():
        async with Client(server, raise_exceptions=True) as client:
            listed = await client.list_tools()
            assert "governed_execute" in {tool.name for tool in listed.tools}

            args = {"text": "hello"}
            token = permit_to_mapping(permit_for(args))
            data = {"name": "repeat", "arguments": args, "permit": token}
            accepted = await client.call_tool("governed_execute", data)
            assert not accepted.is_error
            body = json.loads(accepted.content[0].text)
            assert body["result"] == "hello"
            assert body["request_id"].startswith("mcp-")
            assert called == ["hello"]

            duplicate = await client.call_tool("governed_execute", data)
            assert duplicate.is_error
            assert called == ["hello"]

            unsigned = await client.call_tool(
                "governed_execute",
                {"name": "repeat", "arguments": {"text": "no permit"}},
            )
            assert unsigned.is_error
            assert called == ["hello"]

            wrong_actor = await client.call_tool(
                "governed_execute",
                {
                    "name": "repeat",
                    "arguments": {"text": "wrong"},
                    "permit": permit_to_mapping(permit_for({"text": "wrong"}, subject="bob")),
                },
            )
            assert wrong_actor.is_error
            assert called == ["hello"]

            invalid = await client.call_tool(
                "governed_execute",
                {"name": "repeat", "arguments": {"text": "wrong"}, "permit": {"no": "fields"}},
            )
            assert invalid.is_error
            assert called == ["hello"]

            unknown = await client.call_tool(
                "governed_execute",
                {"name": "not-registered", "arguments": {}},
            )
            assert unknown.is_error
            assert called == ["hello"]

    asyncio.run(scenario())
    assert len(kernel.export_evidence().ledger_entries) >= 3


def test_factory_requires_explicit_policy_trusted_actor_and_unique_tools():
    kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id="mcp-v2-deny-default", variant="strict", clock=VirtualClock(1000)))

    with pytest.raises(ValueError, match="explicit"):
        create_official_mcp_server(kernel, actor="alice", handlers={"repeat": lambda text: text})

    kernel = kernel_with_explicit_policy()
    with pytest.raises(ValueError, match="trusted"):
        create_official_mcp_server(kernel, actor="*", handlers={"repeat": lambda text: text})
    with pytest.raises(ValueError, match="required"):
        create_official_mcp_server(kernel, actor="alice", handlers={})
    with pytest.raises(ValueError, match="not allowed"):
        create_official_mcp_server(kernel, actor="bob", handlers={"repeat": lambda text: text})
    with pytest.raises(ValueError, match="allowlist"):
        create_official_mcp_server(kernel, actor="alice", handlers={"unknown": lambda text: text})
    with pytest.raises(ValueError, match="callable"):
        create_official_mcp_server(kernel, actor="alice", handlers={"repeat": "not callable"})

    kernel._dispatcher.registry.register("repeat", lambda text: text)
    with pytest.raises(ValueError, match="collides"):
        create_official_mcp_server(kernel, actor="alice", handlers={"repeat": lambda text: text})


def test_real_stdio_subprocess_negotiates_and_denies_without_permit():
    """The official client launches the actual example through stdio."""
    import pathlib
    import sys

    from mcp import StdioServerParameters

    example = (
        pathlib.Path(__file__).resolve().parents[1]
        / "examples"
        / "12_official_mcp_sdk_v2_stdio.py"
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(example)],
        env={"SHARDS_KERNEL_MCP_KEY": "test-only-32-byte-key-for-stdio-process-12345"},
    )

    async def scenario():
        async with Client(parameters) as client:
            assert client.protocol_version is not None
            listed = await client.list_tools()
            assert "governed_execute" in {tool.name for tool in listed.tools}
            denied = await client.call_tool(
                "governed_execute",
                {"name": "repeat", "arguments": {"text": "do-not-execute"}},
            )
            assert denied.is_error

    asyncio.run(scenario())


def test_public_only_ed25519_authorisation_through_official_mcp_client():
    """An official MCP client uses a signed permit; server has no signing key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from shards_kernel.issuer import sign_v2_permit
    from shards_kernel.permits import PublicVerificationKey

    private_key = Ed25519PrivateKey.generate()  # Trusted test issuer, not in server.
    audience = "mcp-ed25519-verifier"
    verifier = PublicVerificationKey(
        issuer="operator",
        audience=audience,
        public_key=private_key.public_key().public_bytes_raw(),
    )
    kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id=audience, variant="strict", clock=VirtualClock(1000)))
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"alice"}),
            allowed_tools=frozenset({"repeat"}),
        )
    )
    kernel.set_public_verifiers({"operator-ed": verifier})
    called = []
    server = create_official_mcp_server(
        kernel, actor="alice", handlers={"repeat": lambda text: called.append(text) or text}
    )
    permit = sign_v2_permit(
        (
            PermitBuilder()
            .issuer("operator")
            .subject("alice")
            .jurisdiction("default")
            .action("repeat")
            .params({"text": "approved"})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(2000)
            .proposal_hash("human-approved")
            .build_unsigned_v2(key_id="operator-ed", audience=audience)
        ),
        private_key,
    )

    async def exercise():
        async with Client(server, raise_exceptions=True) as client:
            payload = {
                "name": "repeat",
                "arguments": {"text": "approved"},
                "permit": permit_to_mapping(permit),
            }
            allowed = await client.call_tool("governed_execute", payload)
            assert not allowed.is_error
            assert json.loads(allowed.content[0].text)["result"] == "approved"
            assert called == ["approved"]
            replay = await client.call_tool("governed_execute", payload)
            assert replay.is_error
            assert called == ["approved"]
            changed = dict(payload)
            changed["arguments"] = {"text": "not approved"}
            denied = await client.call_tool("governed_execute", changed)
            assert denied.is_error
            assert called == ["approved"]

    asyncio.run(exercise())
    assert kernel._keyring == {}
