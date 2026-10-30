"""Shards-Kernel — Deterministic Control Planes for AI Systems.

Public API surface is defined in shards_kernel.api. Only items exported there
are part of the supported, stable interface. Everything else is internal
and subject to change without notice.

Usage:
    from shards_kernel import StrictKernel, KernelRequest, Decision
    # or explicitly:
    from shards_kernel.api import StrictKernel, KernelRequest, Decision
"""

# Re-export the public API surface
from shards_kernel.api import *  # noqa: F401, F403
from shards_kernel.api import __all__ as _api_all

# Version
from shards_kernel._version import __version__

# Errors (also part of public surface, but kept separate for clarity)
from shards_kernel.common.errors import (
    KernelError,
    BootError,
    StateError,
    JurisdictionError,
    AmbiguityError,
    ToolError,
    AuditError,
)

# Evidence bundle type
from shards_kernel.common.types import EvidenceBundle

__all__ = [
    "__version__",
    # Errors
    "KernelError",
    "BootError",
    "StateError",
    "JurisdictionError",
    "AmbiguityError",
    "ToolError",
    "AuditError",
    # Evidence
    "EvidenceBundle",
    # Plus everything from api.py
    *_api_all,
]
