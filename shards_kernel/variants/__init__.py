"""Kernel variants with different enforcement postures."""

from shards_kernel.variants.base import Kernel
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel

__all__ = [
    "Kernel",
    "StrictKernel",
    "PermissiveKernel",
    "EvidenceFirstKernel",
    "DualChannelKernel",
]
