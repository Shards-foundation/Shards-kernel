"""Tests for async kernel wrappers and helper control flow."""

import asyncio
import pytest

from shards_kernel.async_support.async_kernel import (
    AsyncStrictKernel,
    submit_batch,
    submit_with_retry,
    submit_with_timeout,
)
from shards_kernel.common.errors import StateError
from shards_kernel.common.types import (
    Decision,
    KernelRequest,
    KernelState,
    ReceiptStatus,
    KernelReceipt,
)


def make_request(request_id="r"):
    return KernelRequest(
        request_id=request_id,
        ts_ms=0,
        actor="operator",
        intent="inspect",
        params={},
    )


def fake_receipt(status):
    return KernelReceipt(
        request_id="r",
        status=status,
        state_from=KernelState.IDLE,
        state_to=KernelState.IDLE,
        ts_ms=0,
        decision=Decision.DENY,
    )


def test_async_kernel_lifecycle_and_batch_submission():
    async def scenario():
        kernel = AsyncStrictKernel("async-test")
        assert kernel.state == KernelState.IDLE
        kernel.set_policy(kernel.kernel.policy)
        kernel.set_keyring({})
        receipts = await submit_batch(kernel, [make_request("a"), make_request("b")])
        assert len(receipts) == 2
        assert [receipt.request_id for receipt in receipts] == ["a", "b"]
        assert kernel.export_evidence().kernel_id == "async-test"
        halted = await kernel.halt("test halt")
        assert halted.state_to == KernelState.HALTED
        assert kernel.state == KernelState.HALTED

    asyncio.run(scenario())


def test_submit_batch_uses_matching_permit_list():
    async def scenario():
        class FakeAsyncKernel:
            def __init__(self):
                self.seen = []

            async def submit(self, request, permit):
                self.seen.append((request.request_id, permit))
                return fake_receipt(ReceiptStatus.ACCEPTED)

        kernel = FakeAsyncKernel()
        await submit_batch(kernel, [make_request("a"), make_request("b")], ["pa", "pb"])
        assert kernel.seen == [("a", "pa"), ("b", "pb")]

    asyncio.run(scenario())


def test_submit_with_timeout_returns_or_times_out():
    async def scenario():
        class FastKernel:
            async def submit(self, request, permit):
                return fake_receipt(ReceiptStatus.ACCEPTED)

        result = await submit_with_timeout(FastKernel(), make_request(), timeout=1)
        assert result.status == ReceiptStatus.ACCEPTED

        class SlowKernel:
            async def submit(self, request, permit):
                await asyncio.sleep(0.05)
                return fake_receipt(ReceiptStatus.ACCEPTED)

        with pytest.raises(asyncio.TimeoutError):
            await submit_with_timeout(SlowKernel(), make_request(), timeout=0.001)

    asyncio.run(scenario())


def test_submit_with_retry_retries_failed_receipts_then_stops():
    async def scenario():
        class FlakyKernel:
            def __init__(self):
                self.calls = 0

            async def submit(self, request, permit):
                self.calls += 1
                status = ReceiptStatus.FAILED if self.calls < 3 else ReceiptStatus.ACCEPTED
                return fake_receipt(status)

        kernel = FlakyKernel()
        result = await submit_with_retry(kernel, make_request(), max_retries=3)
        assert result.status == ReceiptStatus.ACCEPTED
        assert kernel.calls == 3

        class HaltKernel:
            async def submit(self, request, permit):
                raise StateError("halted")

        with pytest.raises(StateError):
            await submit_with_retry(HaltKernel(), make_request())

        class AlwaysFailed:
            async def submit(self, request, permit):
                return fake_receipt(ReceiptStatus.FAILED)

        result = await submit_with_retry(AlwaysFailed(), make_request(), max_retries=1)
        assert result.status == ReceiptStatus.FAILED

    asyncio.run(scenario())
