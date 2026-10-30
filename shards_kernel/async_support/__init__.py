"""
Shards-Kernel Async Module

Provides async/await support for kernel operations.
"""

from shards_kernel.async_support.async_kernel import (
    AsyncStrictKernel,
    AsyncPermissiveKernel,
    AsyncEvidenceFirstKernel,
    AsyncDualChannelKernel,
)
from shards_kernel.async_support.async_dispatcher import AsyncDispatcher

__all__ = [
    "AsyncStrictKernel",
    "AsyncPermissiveKernel",
    "AsyncEvidenceFirstKernel",
    "AsyncDualChannelKernel",
    "AsyncDispatcher",
]
