"""Async registry and wrapper tests."""

import asyncio

from kernels.async_support.async_dispatcher import (
    AsyncDispatcher,
    AsyncToolRegistry,
    create_default_async_registry,
)
from kernels.common.types import ToolCall


def test_registry_decorator_and_direct_registration_metadata():
    registry = AsyncToolRegistry()

    @registry.register("sync", description="sync handler", params_schema={"x": "int"})
    def sync_handler(value):
        return value

    async def async_handler(value):
        return value

    registry.register_tool("async", async_handler, description="async handler")
    assert registry.get("sync") is sync_handler
    assert registry.get("missing") is None
    assert registry.has_tool("sync")
    assert not registry.has_tool("missing")
    assert registry.list_tools() == ["sync", "async"]
    assert registry.get_metadata("sync") == {
        "name": "sync",
        "description": "sync handler",
        "params_schema": {"x": "int"},
        "is_async": False,
    }
    assert registry.get_metadata("async")["is_async"] is True
    assert registry.get_metadata("missing") is None


def test_default_registry_contains_expected_mock_tools():
    registry = create_default_async_registry()
    assert registry.list_tools() == ["echo", "delay", "fetch"]
    assert registry.get_metadata("echo")["params_schema"]["message"]["type"] == "string"


def test_dispatcher_fails_closed_and_batch_preserves_order():
    async def scenario():
        dispatcher = AsyncDispatcher(AsyncToolRegistry())
        results = await dispatcher.dispatch_batch(
            [ToolCall("first"), ToolCall("second")], concurrency=1
        )
        assert len(results) == 2
        assert all(not result.success for result in results)
        assert all("MISSING_PERMIT" in result.error for result in results)
        single = await dispatcher.dispatch(ToolCall("third"), timeout=0)
        assert single.success is False
        assert "AsyncKernel" in single.error

    asyncio.run(scenario())


def test_mock_async_echo_fetch_and_delay():
    from kernels.async_support.async_dispatcher import async_delay, async_echo, async_fetch

    async def scenario():
        assert await async_echo({"message": "hello"}) == {"echoed": "hello"}
        assert await async_delay({"seconds": 0}) == {"delayed": 0}
        fetched = await async_fetch({"url": "https://example.invalid"})
        assert fetched["url"] == "https://example.invalid"
        assert fetched["status"] == 200

    asyncio.run(scenario())
