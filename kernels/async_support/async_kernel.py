"""Async wrappers around the synchronous kernels.

The async classes do not implement a second state machine. Every submit,
halt, and ledger load runs on the synchronous kernel, so permit binding,
intent-before-execute, halt-on-fault, and permit budgets cannot drift.
"""

from __future__ import annotations

import asyncio
from typing import Optional, Type

from kernels.common.errors import StateError
from kernels.common.types import (
    KernelConfig,
    KernelReceipt,
    KernelRequest,
    KernelState,
    VirtualClock,
)
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.permits import PermitToken
from kernels.variants.base import BaseKernel
from kernels.variants.dual_channel_kernel import DualChannelKernel
from kernels.variants.evidence_first_kernel import EvidenceFirstKernel
from kernels.variants.permissive_kernel import PermissiveKernel
from kernels.variants.strict_kernel import StrictKernel


class AsyncKernel:
    """Serialize async calls onto one synchronous kernel."""

    def __init__(self, kernel: BaseKernel) -> None:
        self.kernel = kernel
        self._lock = asyncio.Lock()

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

    async def submit(
        self,
        request: KernelRequest,
        permit_token: Optional[PermitToken] = None,
    ) -> KernelReceipt:
        """Submit one request. The synchronous kernel does the governance."""
        async with self._lock:
            return await asyncio.to_thread(
                self.kernel.submit, request, permit_token
            )

    async def halt(self, reason: str = "halt") -> KernelReceipt:
        """Halt the underlying kernel."""
        async with self._lock:
            return await asyncio.to_thread(self.kernel.halt, reason)

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
    permits = permits or [None] * len(requests)
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
    """Submit a request and raise TimeoutError if it overruns."""
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
    """Retry a failed tool execution. A halt is not retried."""
    last: Optional[KernelReceipt] = None
    for attempt in range(max_retries + 1):
        try:
            last = await kernel.submit(request, permit_token)
        except StateError:
            raise
        if last.status.value != "FAILED":
            return last
        if attempt < max_retries and backoff:
            await asyncio.sleep(backoff * (2**attempt))
    assert last is not None
    return last
