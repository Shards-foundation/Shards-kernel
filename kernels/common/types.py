"""Core type definitions for Kernels."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class KernelState(Enum):
    """Defined states for the kernel state machine."""

    BOOTING = "BOOTING"
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    ARBITRATING = "ARBITRATING"
    EXECUTING = "EXECUTING"
    AUDITING = "AUDITING"
    COMPLETED = "COMPLETED"
    HALTED = "HALTED"


class Decision(Enum):
    """Possible decisions from kernel arbitration."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"


class ReceiptStatus(Enum):
    """Status of a kernel receipt."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ToolCall:
    """Specification of a tool invocation."""

    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KernelRequest:
    """A request submitted to the kernel for arbitration."""

    request_id: str
    ts_ms: int
    actor: str
    intent: str
    tool_call: Optional[ToolCall] = None
    params: dict[str, Any] = field(default_factory=dict)
    evidence: Optional[str] = None


@dataclass(frozen=True)
class KernelReceipt:
    """Receipt returned by the kernel after processing a request."""

    request_id: str
    status: ReceiptStatus
    state_from: KernelState
    state_to: KernelState
    ts_ms: int
    decision: Decision
    error: Optional[str] = None
    evidence_hash: Optional[str] = None
    tool_result: Optional[Any] = None


@dataclass(frozen=True)
class AuditEntry:
    """A single entry in the append-only audit ledger."""

    ledger_seq: int  # Monotonic sequence number for deterministic ordering
    prev_hash: str
    entry_hash: str
    ts_ms: int
    request_id: str
    actor: str
    intent: str
    decision: Decision
    state_from: KernelState
    state_to: KernelState
    tool_name: Optional[str] = None
    params_hash: Optional[str] = None
    evidence_hash: Optional[str] = None
    error: Optional[str] = None

    # Permit-related fields (added in v0.2.0)
    permit_digest: Optional[str] = None
    permit_verification: Optional[str] = None  # "ALLOW" | "DENY"
    permit_denial_reasons: tuple[str, ...] = field(default_factory=tuple)
    proposal_hash: Optional[str] = None
    permit_nonce: Optional[str] = None  # For ledger-backed replay protection
    permit_issuer: Optional[str] = None  # Issuer identity for nonce reconstruction
    permit_subject: Optional[str] = None  # Subject identity for nonce reconstruction
    permit_max_executions: Optional[int] = (
        None  # Max executions for nonce reconstruction
    )
    # "intent" is appended before a tool runs; "outcome" records what ran.
    audit_phase: Optional[str] = None


@dataclass(frozen=True)
class EvidenceBundle:
    """Exportable evidence bundle with full ledger and verification data."""

    ledger_entries: tuple[AuditEntry, ...]
    root_hash: str
    exported_at_ms: int
    kernel_id: str
    variant: str


@dataclass(frozen=True)
class DecisionEnvelope:
    """
    Immutable binding between permit verification and execution.

    This envelope prevents TOCTOU (time-of-check-time-of-use) bugs by
    binding the verified permit to the exact request parameters that
    will be executed. The envelope is created during VALIDATING and
    flows through ARBITRATING → EXECUTING → AUDITING without modification.

    Security property:
        "The permit that was verified is cryptographically bound to
        the parameters that were executed."

    Fields must match the permit that authorized them, enforced by hash chain.
    """

    # Traceability chain
    proposal_hash: str  # Hash of proposal that initiated this request
    permit_digest: str  # Permit ID that authorized execution

    # Verified constraints from permit
    constraints: dict[str, Any]  # Effective constraints from permit
    max_time_ms: Optional[int]  # Maximum execution time allowed
    forbidden_params: tuple[str, ...]  # Parameters that must not be present

    # Execution binding
    tool_name: str  # Tool to execute (must match permit.action)
    params: dict[str, Any]  # Parameters to execute (must satisfy constraints)

    # Decision metadata
    decision: Decision  # ALLOW or DENY
    verified_at_ms: int  # Timestamp when verification occurred
    actor: str  # Actor who submitted request (must match permit.subject)


class VirtualClock:
    """Deterministic clock for kernel operations."""

    def __init__(self, initial_ms: int = 0) -> None:
        """Initialize clock with starting time."""
        self._current_ms = initial_ms

    def now_ms(self) -> int:
        """Return current time in milliseconds."""
        return self._current_ms

    def advance(self, delta_ms: int) -> None:
        """Advance clock by specified milliseconds."""
        if delta_ms < 0:
            raise ValueError("Clock cannot move backward")
        self._current_ms += delta_ms

    def set(self, ts_ms: int) -> None:
        """Set clock to specific time."""
        if ts_ms < self._current_ms:
            raise ValueError("Clock cannot move backward")
        self._current_ms = ts_ms


# Type aliases for SDK compatibility
Request = KernelRequest
Receipt = KernelReceipt


@dataclass
class KernelConfig:
    """Configuration for a kernel instance."""

    kernel_id: str
    variant: str
    fail_closed: bool = True
    require_jurisdiction: bool = True
    require_audit: bool = True
    clock: VirtualClock = field(default_factory=VirtualClock)
    hash_alg: str = "sha256"
    max_param_bytes: int = 65536
    max_intent_length: int = 4096
    # Jurisdiction name checked against permit.jurisdiction. Defaults to the
    # historical constant so existing permits that say "default" keep working.
    jurisdiction: str = "default"
    # Development-only escape hatch. When True, a non-strict kernel may run a
    # tool with no permit. StrictKernel forces this off. Never enable it where
    # an authorisation decision matters.
    allow_insecure_unpermitted_execution: bool = False
