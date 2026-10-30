"""Synchronous and asynchronous SDK client integration tests."""

import asyncio

from shards_kernel.integrations.wire import boot_strict_kernel
from shards_kernel.sdk.builder import request
from shards_kernel.sdk.client import (
    AsyncKernelClient,
    KernelClient,
    create_async_client,
    create_client,
)
from shards_kernel.sdk.server import KernelServer


def test_sync_client_round_trip_against_local_server():
    server = KernelServer(boot_strict_kernel("sync-client-test"), port=0)
    server.start(blocking=False)
    url = f"http://127.0.0.1:{server._server.server_address[1]}"
    try:
        client = KernelClient(url, api_key="test-key", timeout=2)
        assert client.health()["status"] == "healthy"
        assert client.status()["kernel_id"] == "sync-client-test"
        assert "ledger_entries" in client.evidence()
        assert "allowed_actors" in client.policy()

        req = request().with_id("sync-1").with_actor("operator").with_intent("inspect").with_tool("echo", {"text": "x"}).build()
        receipt = client.submit(req)
        assert receipt.request_id == "sync-1"
        assert receipt.decision.value in {"DENY", "HALT"}
        batch = client.submit_batch([
            request().with_id("sync-2").with_actor("operator").with_intent("inspect").build()
        ])
        assert len(batch) == 1
        assert batch[0].request_id == "sync-2"
        assert create_client(url).status()["kernel_id"] == "sync-client-test"
        assert client.halt()["status"] == "halted"
    finally:
        server.stop()


def test_async_client_round_trip_against_local_server():
    server = KernelServer(boot_strict_kernel("async-client-test"), port=0)
    server.start(blocking=False)
    url = f"http://127.0.0.1:{server._server.server_address[1]}"

    async def scenario():
        client = AsyncKernelClient(url, timeout=2)
        assert (await client.health())["status"] == "healthy"
        assert (await client.status())["kernel_id"] == "async-client-test"
        assert "ledger_entries" in await client.evidence()
        req = request().with_id("async-1").with_actor("operator").with_intent("inspect").build()
        receipt = await client.submit(req)
        assert receipt.request_id == "async-1"
        batch = await client.submit_batch([
            request().with_id("async-2").with_actor("operator").with_intent("inspect").build()
        ], concurrency=1)
        assert batch[0].request_id == "async-2"
        assert (await client.halt())["status"] == "halted"
        assert create_async_client(url).config.base_url == url

    try:
        asyncio.run(scenario())
    finally:
        server.stop()
