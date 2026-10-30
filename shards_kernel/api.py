"""Public, supported API surface for Shards-Kernel.

If it isn't imported here and re-exported via __all__, treat it as internal
and subject to change. This file is the compatibility contract.

Usage:
    from shards_kernel.api import Kernel, KernelRequest, KernelReceipt, Decision
    # or
    from shards_kernel import Kernel, KernelRequest, KernelReceipt, Decision
"""

from __future__ import annotations

# -----------------------------------------------------------------------------
# Core types (stable)
# -----------------------------------------------------------------------------
from shards_kernel.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelReceipt,
    KernelState,
    ReceiptStatus,
    ToolCall,
    VirtualClock,
)

# -----------------------------------------------------------------------------
# Interfaces / protocols (stable)
# -----------------------------------------------------------------------------
from shards_kernel.variants.base import Kernel, BaseKernel

# -----------------------------------------------------------------------------
# Kernel variants (stable)
# -----------------------------------------------------------------------------
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel
from shards_kernel.variants.evidence_first_kernel import EvidenceFirstKernel
from shards_kernel.variants.dual_channel_kernel import DualChannelKernel

# -----------------------------------------------------------------------------
# Tooling surface (stable)
# -----------------------------------------------------------------------------
from shards_kernel.execution.tools import ToolRegistry
from shards_kernel.core.runtime import (
    Artifact,
    ArtifactRef,
    ExecutionIdentity,
    ExecutionContext,
    GraphBudget,
    GraphExecutionResult,
    KernelRuntime,
    RuntimeEvent,
    RuntimeExecutionResult,
    RuntimeState,
    TaskGraph,
    TaskNode,
)

# -----------------------------------------------------------------------------
# Evidence surface (stable)
# -----------------------------------------------------------------------------
from shards_kernel.audit.ledger import AuditLedger
from shards_kernel.audit.replay import (
    replay_and_verify,
    verify_evidence_bundle,
    ReplayResult,
)

# -----------------------------------------------------------------------------
# Jurisdiction (stable)
# -----------------------------------------------------------------------------
from shards_kernel.jurisdiction.policy import JurisdictionPolicy

# -----------------------------------------------------------------------------
# Permit System (v0.2.0+)
# -----------------------------------------------------------------------------
from shards_kernel.permits import (
    NonceRegistry,
    PermitBuilder,
    PermitToken,
    PermitVerificationResult,
    canonical_permit_bytes,
    compute_permit_id,
    generate_nonce,
    sign_permit,
    verify_permit,
    verify_signature,
)

# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------
__all__ = [
    # Core types
    "Decision",
    "KernelConfig",
    "KernelRequest",
    "KernelReceipt",
    "KernelState",
    "ReceiptStatus",
    "ToolCall",
    "VirtualClock",
    # Interfaces
    "Kernel",
    "BaseKernel",
    # Variants
    "StrictKernel",
    "PermissiveKernel",
    "EvidenceFirstKernel",
    "DualChannelKernel",
    # Tooling
    "ToolRegistry",
    "ExecutionContext",
    "ExecutionIdentity",
    "GraphBudget",
    "ArtifactRef",
    "Artifact",
    "TaskNode",
    "TaskGraph",
    "GraphExecutionResult",
    "RuntimeState",
    "KernelRuntime",
    "RuntimeEvent",
    "RuntimeExecutionResult",
    # Evidence
    "AuditLedger",
    "replay_and_verify",
    "verify_evidence_bundle",
    "ReplayResult",
    # Jurisdiction
    "JurisdictionPolicy",
    # Permit System (v0.2.0+)
    "PermitToken",
    "PermitBuilder",
    "PermitVerificationResult",
    "NonceRegistry",
    "canonical_permit_bytes",
    "compute_permit_id",
    "generate_nonce",
    "sign_permit",
    "verify_permit",
    "verify_signature",
]
