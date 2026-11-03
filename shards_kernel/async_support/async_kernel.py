"""Async wrappers around the synchronous shards_kernel.

The async classes do not implement a second state machine. Every submit,
halt, and ledger load runs on the synchronous kernel, so permit binding,
intent-before-execute, halt-on-fault, and permit budgets cannot drift.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional, Type

from shards_kernel.common.errors import StateError
from shards_kernel.common.types import (
    KernelConfig,
    KernelReceipt,
    KernelRequest,
    KernelState,
    VirtualClock,
)
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PermitToken
from shards_kernel.variants.base import BaseKernel
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.strict_kernel import StrictKernel


class AsyncKernel:
    """Serialize async calls onto one synchronous kernel."""

    def __init__(self, kernel: BaseKernel) -> None:
        self.kernel = kernel
        # Python 3.9 binds locks at construction. Defer construction until
        # the first running loop, so wrappers can be created synchronously.
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def state(self) -> KernelState:
        """Current kernel state."""
        return self.kernel.get_state()

    def set_keyring(self, keyring: dict[str, bytes]) -> None:
        """Install HMAC keys used to verify permits."""
        self.kernel.set_keyring(keyring)

    def set_policy(self, policy: JurisdictionPolicy) -> None:
        """Replace the jurisdiction policy."""
        self.kernel.set_policy(policy)

    async def _call_serialized(
        self, operation: Callable[..., KernelReceipt], *args: Any
    ) -> KernelReceipt:
        """Keep the lock until the worker finishes, even if its waiter cancels."""
        loop = asyncio.get_running_loop()
        if self._lock is None or (
            self._loop is not loop
            and self._loop is not None
            and self._loop.is_closed()
            and not self._lock.locked()
        ):
            self._lock = asyncio.Lock()
            self._loop = loop
        elif self._loop is not loop:
            raise StateError("AsyncKernel cannot be shared between active event loops")
        lock = self._lock
        await lock.acquire()
        try:
            worker = asyncio.create_task(asyncio.to_thread(operation, *args))
        except BaseException:
            lock.release()
            raise

        def finished(task: asyncio.Task) -> None:
            lock.release()
            # Retrieve exceptions even if the original waiter was cancelled.
            if not task.cancelled():
                task.exception()

        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def submit(
        self,
        request: KernelRequest,
        permit_token: Optional[PermitToken] = None,
    ) -> KernelReceipt:
        """Submit one request. The synchronous kernel does the governance."""
        return await self._call_serialized(self.kernel.submit, request, permit_token)

    async def halt(self, reason: str = "halt") -> KernelReceipt:
        """Halt the underlying kernel."""
        return await self._call_serialized(self.kernel.halt, reason)

    def export_evidence(self):
        """Export the underlying evidence bundle."""
        return self.kernel.export_evidence()


def _boot(kernel_cls: Type[BaseKernel], kernel_id: str, variant: str) -> BaseKernel:
    kernel = kernel_cls()
    kernel.boot(
        KernelConfig(
            kernel_id=kernel_id,
            variant=variant,
            clock=VirtualClock(0),
        )
    )
    return kernel


class AsyncStrictKernel(AsyncKernel):
    """Async view of StrictKernel."""

    def __init__(self, kernel_id: str) -> None:
        super().__init__(_boot(StrictKernel, kernel_id, "strict"))


class AsyncPermissiveKernel(AsyncKernel):
    """Async view of PermissiveKernel."""

    def __init__(self, kernel_id: str) -> None:
        super().__init__(_boot(PermissiveKernel, kernel_id, "permissive"))


class AsyncEvidenceFirstKernel(AsyncKernel):
    """Async view of EvidenceFirstKernel."""

    def __init__(self, kernel_id: str) -> None:
        super().__init__(_boot(EvidenceFirstKernel, kernel_id, "evidence-first"))


class AsyncDualChannelKernel(AsyncKernel):
    """Async view of DualChannelKernel."""

    def __init__(self, kernel_id: str) -> None:
        super().__init__(_boot(DualChannelKernel, kernel_id, "dual-channel"))


async def submit_batch(
    kernel: AsyncKernel,
    requests: list[KernelRequest],
    permits: Optional[list[Optional[PermitToken]]] = None,
) -> list[KernelReceipt]:
    """Submit requests one after another on the kernel lock."""
    if permits is None:
        permits = [None] * len(requests)
    elif len(permits) != len(requests):
        raise ValueError("The number of permits must match the number of requests")
    receipts = []
    for request, permit in zip(requests, permits):
        receipts.append(await kernel.submit(request, permit))
    return receipts


async def submit_with_timeout(
    kernel: AsyncKernel,
    request: KernelRequest,
    timeout: float,
    permit_token: Optional[PermitToken] = None,
) -> KernelReceipt:
    """Stop waiting after timeout; a running tool may continue to have effects.

    The kernel remains serialized until that work finishes. Inspect its audit
    trail before retrying, and use idempotent tools when retries are possible.
    This is not a hard execution deadline.
    """
    return await asyncio.wait_for(
        kernel.submit(request, permit_token), timeout=timeout
    )


async def submit_with_retry(
    kernel: AsyncKernel,
    request: KernelRequest,
    permit_token: Optional[PermitToken] = None,
    max_retries: int = 3,
    backoff: float = 0.0,
) -> KernelReceipt:
    """Retry failed execution only when repeating the tool's effects is safe.

    A failed handler may already have had side effects. Permit replay limits
    still apply independently to each attempt. A halt is not retried.
    """
    if type(max_retries) is not int or max_retries < 0:
        raise ValueError("max_retries must be a non-negative integer")
    for attempt in range(max_retries + 1):
        receipt = await kernel.submit(request, permit_token)
        if receipt.status.value != "FAILED" or attempt == max_retries:
            return receipt
        if backoff:
            await asyncio.sleep(backoff * (2**attempt))
    raise RuntimeError("retry loop did not execute")
