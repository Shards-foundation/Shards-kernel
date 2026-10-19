"""
Permit Token System for KERNELS.

Implements HMAC-based capability tokens that bind authorization scope,
cryptographic verification, replay protection, and audit linkage.

Normative specification: spec/PERMIT_TOKENS.md
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from kernels.common.types import Decision

# ============================================================================
# PERMIT TOKEN DATA MODEL
# ============================================================================


@dataclass(frozen=True)
class PermitToken:
    """
    Immutable capability token authorizing a specific action.

    Invariants:
    - All fields are immutable (frozen dataclass)
    - permit_id is deterministic (content hash of canonical form)
    - Signature is HMAC-SHA256 over canonical encoding
    - Missing/invalid fields cause verification to fail

    See spec/PERMIT_TOKENS.md Section 3 for normative definition.
    """

    # Identity
    permit_id: str
    issuer: str
    subject: str

    # Authorization scope
    jurisdiction: str
    action: str
    params: dict[str, Any]

    # Constraints
    constraints: dict[str, Any]
    max_executions: int

    # Validity window (monotonic time in milliseconds)
    valid_from_ms: int
    valid_until_ms: int

    # Audit linkage
    evidence_hash: str
    proposal_hash: str

    # Replay protection
    nonce: str

    # Cryptographic binding
    signature: str
    key_id: str

    def __post_init__(self) -> None:
        """Validate field constraints at construction time."""
        # Type validation (defense in depth)
        if not isinstance(self.permit_id, str):
            raise ValueError("permit_id must be str")
        if not isinstance(self.issuer, str) or len(self.issuer) == 0:
            raise ValueError("issuer must be non-empty str")
        if not isinstance(self.subject, str) or len(self.subject) == 0:
            raise ValueError("subject must be non-empty str")
        if not isinstance(self.jurisdiction, str) or len(self.jurisdiction) == 0:
            raise ValueError("jurisdiction must be non-empty str")
        if not isinstance(self.action, str) or len(self.action) == 0:
            raise ValueError("action must be non-empty str")
        if not isinstance(self.params, dict):
            raise ValueError("params must be dict")
        if not isinstance(self.constraints, dict):
            raise ValueError("constraints must be dict")
        if not isinstance(self.max_executions, int) or self.max_executions < 1:
            raise ValueError("max_executions must be int >= 1")
        if not isinstance(self.valid_from_ms, int) or self.valid_from_ms < 0:
            raise ValueError("valid_from_ms must be int >= 0")
        if (
            not isinstance(self.valid_until_ms, int)
            or self.valid_until_ms <= self.valid_from_ms
        ):
            raise ValueError("valid_until_ms must be int > valid_from_ms")
        if not isinstance(self.evidence_hash, str):
            raise ValueError("evidence_hash must be str")
        if not isinstance(self.proposal_hash, str) or len(self.proposal_hash) == 0:
            raise ValueError("proposal_hash must be non-empty str")
        if not isinstance(self.nonce, str) or len(self.nonce) < 32:
            raise ValueError("nonce must be str >= 32 chars")
        if not isinstance(self.signature, str):
            raise ValueError("signature must be str")
        if not isinstance(self.key_id, str) or len(self.key_id) == 0:
            raise ValueError("key_id must be non-empty str")


@dataclass(frozen=True)
class PermitVerificationResult:
    """
    Result of permit verification.

    status: ALLOW if all checks pass, DENY otherwise
    reasons: List of denial reason codes (empty if ALLOW)
    """

    status: Decision
    reasons: list[str] = field(default_factory=list)

    def is_allowed(self) -> bool:
        """Check if verification succeeded."""
        return self.status == Decision.ALLOW and len(self.reasons) == 0


@dataclass(frozen=True)
class NonceRecord:
    """
    Record of a nonce usage for replay protection.

    Stored in nonce registry; append-only.
    """

    nonce: str
    issuer: str
    subject: str
    first_seen_ms: int
    use_count: int
    permit_id: str


# ============================================================================
# CANONICAL SERIALIZATION
# ============================================================================


def _sort_dict_recursive(d: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively sort dictionary keys for deterministic serialization.

    Args:
        d: Dictionary to sort

    Returns:
        New dictionary with sorted keys at all nesting levels
    """
    result: dict[str, Any] = {}
    for key in sorted(d.keys()):
        value = d[key]
        if isinstance(value, dict):
            result[key] = _sort_dict_recursive(value)
        elif isinstance(value, list):
            result[key] = [
                _sort_dict_recursive(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    return result


def canonical_permit_bytes(
    permit: PermitToken, exclude_signature: bool = True, exclude_permit_id: bool = False
) -> bytes:
    """
    Produce deterministic byte representation of permit.

    Encoding rules (spec/PERMIT_TOKENS.md Section 4):
    - Alphabetical field ordering
    - Sorted dict keys at all levels
    - Compact JSON (no whitespace)
    - UTF-8 encoding
    - signature excluded by default (signs everything else)
    - permit_id excluded when computing permit ID (bootstrapping)

    Args:
        permit: Permit token to serialize
        exclude_signature: If True, omit signature field (default)
        exclude_permit_id: If True, omit permit_id field (for ID computation)

    Returns:
        UTF-8 encoded compact JSON bytes
    """
    data: dict[str, Any] = {
        "action": permit.action,
        "constraints": _sort_dict_recursive(permit.constraints),
        "evidence_hash": permit.evidence_hash,
        "issuer": permit.issuer,
        "jurisdiction": permit.jurisdiction,
        "key_id": permit.key_id,
        "max_executions": permit.max_executions,
        "nonce": permit.nonce,
        "params": _sort_dict_recursive(permit.params),
        "proposal_hash": permit.proposal_hash,
        "subject": permit.subject,
        "valid_from_ms": permit.valid_from_ms,
        "valid_until_ms": permit.valid_until_ms,
    }

    if not exclude_permit_id:
        data["permit_id"] = permit.permit_id

    if not exclude_signature:
        data["signature"] = permit.signature

    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_permit_id(permit: PermitToken) -> str:
    """
    Compute deterministic permit ID (content hash).

    permit_id = SHA-256(canonical_bytes(permit without ID and signature))

    Args:
        permit: Permit token (with permit_id and signature possibly empty)

    Returns:
        64-character hex string (SHA-256 digest)
    """
    # Exclude both permit_id and signature when computing ID
    canonical = canonical_permit_bytes(
        permit, exclude_signature=True, exclude_permit_id=True
    )
    return hashlib.sha256(canonical).hexdigest()


# ============================================================================
# NONCE GENERATION
# ============================================================================


def generate_nonce() -> str:
    """
    Generate cryptographically random nonce for replay protection.

    Returns:
        32-character hex string (UUID4)
    """
    return uuid.uuid4().hex


def deterministic_nonce(proposal_hash: str, sequence: int) -> str:
    """
    Generate deterministic nonce from proposal hash and sequence.

    Useful for testing and reproducible scenarios.

    Args:
        proposal_hash: Hash of proposal
        sequence: Sequence number (0, 1, 2, ...)

    Returns:
        32-character hex string
    """
    data = f"{proposal_hash}:{sequence}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:32]


# ============================================================================
# HMAC SIGNING AND VERIFICATION
# ============================================================================


def sign_permit(permit: PermitToken, key: bytes, key_id: str) -> PermitToken:
    """
    Sign a permit token with HMAC-SHA256.

    Signing algorithm (spec/PERMIT_TOKENS.md Section 5.2):
    1. Serialize permit to canonical bytes (excluding signature)
    2. Compute HMAC-SHA256(key, canonical_bytes)
    3. Return new permit with signature field populated

    Args:
        permit: Permit with permit_id computed but signature empty
        key: HMAC secret key (32 bytes recommended)
        key_id: Key identifier for rotation support

    Returns:
        New permit with signature and key_id fields populated
    """
    canonical = canonical_permit_bytes(
        permit, exclude_signature=True, exclude_permit_id=False
    )
    sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return replace(permit, signature=sig, key_id=key_id)


def verify_signature(
    permit: PermitToken, keyring: dict[str, bytes]
) -> PermitVerificationResult:
    """
    Verify permit signature against keyring.

    Checks (spec/PERMIT_TOKENS.md Section 6):
    1. Key ID is known in keyring
    2. Signature is valid HMAC-SHA256
    3. Permit ID matches computed hash

    Args:
        permit: Permit to verify
        keyring: Map of key_id -> HMAC secret key

    Returns:
        PermitVerificationResult with ALLOW/DENY and reason codes
    """
    # Check 1: Key ID known
    if permit.key_id not in keyring:
        return PermitVerificationResult(
            status=Decision.DENY, reasons=["UNKNOWN_KEY_ID"]
        )

    key = keyring[permit.key_id]

    # Check 2: Signature valid
    canonical = canonical_permit_bytes(
        permit, exclude_signature=True, exclude_permit_id=False
    )
    expected_sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(permit.signature, expected_sig):
        return PermitVerificationResult(
            status=Decision.DENY, reasons=["SIGNATURE_INVALID"]
        )

    # Check 3: Permit ID valid
    expected_id = compute_permit_id(permit)
    if permit.permit_id != expected_id:
        return PermitVerificationResult(
            status=Decision.DENY, reasons=["PERMIT_ID_MISMATCH"]
        )

    return PermitVerificationResult(status=Decision.ALLOW, reasons=[])


# ============================================================================
# NONCE REGISTRY (Replay Protection)
# ============================================================================


class NonceRegistry:
    """
    Append-only registry for tracking nonce usage (replay protection).

    Thread-safety: NOT thread-safe; synchronization is caller's responsibility.
    Persistence: In-memory; caller must persist via audit ledger.
    """

    def __init__(self) -> None:
        """Initialize empty nonce registry."""
        self._registry: dict[tuple[str, str, str], NonceRecord] = {}

    def check_and_record(
        self,
        nonce: str,
        issuer: str,
        subject: str,
        permit_id: str,
        max_executions: int,
        current_time_ms: int,
    ) -> bool:
        """
        Check if nonce is fresh and record usage.

        Args:
            nonce: Nonce value from permit
            issuer: Issuer identity
            subject: Subject identity
            permit_id: Permit identifier
            max_executions: Maximum allowed uses
            current_time_ms: Current monotonic time

        Returns:
            True if nonce is fresh (allow execution)
            False if replay detected (deny execution)
        """
        key = (nonce, issuer, subject)

        if key not in self._registry:
            # First use: record it
            self._registry[key] = NonceRecord(
                nonce=nonce,
                issuer=issuer,
                subject=subject,
                first_seen_ms=current_time_ms,
                use_count=1,
                permit_id=permit_id,
            )
            return True  # Fresh nonce

        # Nonce previously seen
        record = self._registry[key]

        if record.use_count >= max_executions:
            return False  # Replay: exceeded max uses

        # Increment use count
        self._registry[key] = replace(record, use_count=record.use_count + 1)
        return True  # Within allowed uses

    def can_consume(
        self,
        nonce: str,
        issuer: str,
        subject: str,
        max_executions: int,
    ) -> bool:
        """Return whether another use would be allowed, without recording it.

        Denied requests must call this (or skip the registry entirely) so a
        rejection cannot exhaust ``max_executions``.
        """
        key = (nonce, issuer, subject)
        record = self._registry.get(key)
        if record is None:
            return True
        return record.use_count < max_executions

    def get_record(self, nonce: str, issuer: str, subject: str) -> NonceRecord | None:
        """Retrieve nonce record if it exists."""
        key = (nonce, issuer, subject)
        return self._registry.get(key)

    def has_nonce(self, nonce: str, issuer: str, subject: str) -> bool:
        """Check if nonce has been seen before."""
        key = (nonce, issuer, subject)
        return key in self._registry

    def size(self) -> int:
        """Return number of nonces tracked."""
        return len(self._registry)


# ============================================================================
# PERMIT VERIFICATION PIPELINE (Fail-Closed)
# ============================================================================


def verify_permit(
    permit: PermitToken,
    keyring: dict[str, bytes],
    nonce_registry: NonceRegistry,
    current_time_ms: int,
    current_jurisdiction: str,
    allowed_actions: frozenset[str],
    request_actor: str,
    request_params: dict[str, Any],
    request_evidence: str | None = None,
    commit_use: bool = True,
) -> PermitVerificationResult:
    """
    Comprehensive fail-closed permit verification.

    Verification checklist (spec/PERMIT_TOKENS.md Section 6):
    1. Key ID known
    2. Signature valid
    3. Permit ID valid
    4. Time window valid
    5. Jurisdiction matches
    6. Action allowed
    7. Subject matches request actor
    8. Request params satisfy permit params
    9. Nonce fresh (no replay)
    10. Execution count not exceeded
    11. Constraints satisfied

    Any check failure → DENY with reason codes.

    Args:
        permit: Permit to verify
        keyring: Map of key_id -> HMAC secret
        nonce_registry: Nonce registry for replay protection
        current_time_ms: Current monotonic time
        current_jurisdiction: Kernel's active jurisdiction
        allowed_actions: Set of allowed action names
        request_actor: Actor identity from request
        request_params: Parameters from request
        request_evidence: Evidence string on the request, if any
        commit_use: When False, replay state is checked but not recorded.
            The kernel records a use only after the request is authorised.

    Returns:
        PermitVerificationResult with ALLOW/DENY and reason codes
    """
    reasons: list[str] = []

    # Checks 1-3: Cryptographic verification
    sig_result = verify_signature(permit, keyring)
    if not sig_result.is_allowed():
        return sig_result

    # Check 4: Time window
    if current_time_ms < permit.valid_from_ms:
        reasons.append("NOT_YET_VALID")
    if current_time_ms > permit.valid_until_ms:
        reasons.append("EXPIRED")

    # Check 5: Jurisdiction match
    if permit.jurisdiction != current_jurisdiction:
        reasons.append("JURISDICTION_MISMATCH")

    # Check 6: Action allowed
    if permit.action not in allowed_actions:
        reasons.append("ACTION_NOT_ALLOWED")

    # Check 7: Subject match
    if permit.subject != request_actor:
        reasons.append("SUBJECT_MISMATCH")

    # Check 8: Params match (request params must be subset of permit params)
    if not _params_satisfy_permit(request_params, permit.params):
        reasons.append("PARAMS_MISMATCH")

    # Check 11 before nonce accounting: a rejected request must not consume a use.
    constraint_violations = _validate_constraints(
        permit.constraints,
        request_params,
        request_evidence,
    )
    reasons.extend(constraint_violations)

    if reasons:
        return PermitVerificationResult(status=Decision.DENY, reasons=reasons)

    # Check 9/10: Nonce fresh. Record only when the caller is committing a use.
    if commit_use:
        nonce_ok = nonce_registry.check_and_record(
            nonce=permit.nonce,
            issuer=permit.issuer,
            subject=permit.subject,
            permit_id=permit.permit_id,
            max_executions=permit.max_executions,
            current_time_ms=current_time_ms,
        )
    else:
        nonce_ok = nonce_registry.can_consume(
            nonce=permit.nonce,
            issuer=permit.issuer,
            subject=permit.subject,
            max_executions=permit.max_executions,
        )

    if not nonce_ok:
        return PermitVerificationResult(
            status=Decision.DENY, reasons=["REPLAY_DETECTED"]
        )

    return PermitVerificationResult(status=Decision.ALLOW, reasons=[])


def _params_satisfy_permit(
    request_params: dict[str, Any], permit_params: dict[str, Any]
) -> bool:
    """
    Check if request params are satisfied by permit params.

    Rule: Request params must be a subset of permit params (equal or more restrictive).

    Args:
        request_params: Parameters from request
        permit_params: Parameters authorized by permit

    Returns:
        True if request params satisfy permit, False otherwise
    """
    # All request params must be present in permit params
    for key, value in request_params.items():
        if key not in permit_params:
            return False  # Request has param not in permit

        # Values must match exactly (strict equality)
        # Future: Could support range checks, regex, etc.
        if permit_params[key] != value:
            return False  # Param value mismatch

    return True


# Constraints the kernel actually enforces. Anything else fails closed.
_IMPLEMENTED_CONSTRAINTS = frozenset(
    {"forbidden_params", "require_evidence", "max_time_ms"}
)
# Named in the docs but not enforced at execution time. Accepting them would
# look like a control and do nothing, so they are rejected.
_UNIMPLEMENTED_CONSTRAINTS = frozenset({"max_memory_mb", "allowed_domains"})


def _validate_constraints(
    constraints: dict[str, Any],
    request_params: dict[str, Any],
    request_evidence: str | None = None,
) -> list[str]:
    """
    Validate request against permit constraints.

    Unknown keys and constraints that are not implemented are rejected.
    ``require_evidence`` requires a non-empty request evidence string.

    Args:
        constraints: Constraints from permit
        request_params: Parameters from request
        request_evidence: Evidence supplied with the request, if any

    Returns:
        List of violation reason codes (empty = all satisfied)
    """
    violations: list[str] = []

    if "forbidden_params" in constraints:
        forbidden = constraints["forbidden_params"]
        if not isinstance(forbidden, list):
            violations.append("CONSTRAINT_MALFORMED_FORBIDDEN_PARAMS")
        else:
            for param in forbidden:
                if param in request_params:
                    violations.append(f"FORBIDDEN_PARAM_DETECTED:{param}")

    if "require_evidence" in constraints:
        flag = constraints["require_evidence"]
        if not isinstance(flag, bool):
            violations.append("CONSTRAINT_MALFORMED_REQUIRE_EVIDENCE")
        elif flag and not (isinstance(request_evidence, str) and request_evidence.strip()):
            violations.append("REQUIRE_EVIDENCE_MISSING")

    if "max_time_ms" in constraints and not isinstance(constraints["max_time_ms"], int):
        violations.append("CONSTRAINT_MALFORMED_MAX_TIME_MS")

    for key in constraints:
        if key in _IMPLEMENTED_CONSTRAINTS:
            continue
        if key in _UNIMPLEMENTED_CONSTRAINTS:
            violations.append(f"CONSTRAINT_UNIMPLEMENTED:{key}")
        else:
            violations.append(f"CONSTRAINT_UNKNOWN:{key}")

    return violations


# ============================================================================
# PERMIT BUILDER (Convenience)
# ============================================================================


class PermitBuilder:
    """
    Builder for constructing PermitToken objects.

    Provides fluent interface for setting fields and automatic ID/signature computation.
    """

    def __init__(self) -> None:
        """Initialize empty builder."""
        self._issuer: str = ""
        self._subject: str = ""
        self._jurisdiction: str = ""
        self._action: str = ""
        self._params: dict[str, Any] = {}
        self._constraints: dict[str, Any] = {}
        self._max_executions: int = 1
        self._valid_from_ms: int = 0
        self._valid_until_ms: int = 0
        self._evidence_hash: str = ""
        self._proposal_hash: str = ""
        self._nonce: str = ""

    def issuer(self, issuer: str) -> PermitBuilder:
        """Set issuer identity."""
        self._issuer = issuer
        return self

    def subject(self, subject: str) -> PermitBuilder:
        """Set subject (worker) identity."""
        self._subject = subject
        return self

    def jurisdiction(self, jurisdiction: str) -> PermitBuilder:
        """Set jurisdiction."""
        self._jurisdiction = jurisdiction
        return self

    def action(self, action: str) -> PermitBuilder:
        """Set action (tool name)."""
        self._action = action
        return self

    def params(self, params: dict[str, Any]) -> PermitBuilder:
        """Set parameters."""
        self._params = params
        return self

    def constraints(self, constraints: dict[str, Any]) -> PermitBuilder:
        """Set constraints."""
        self._constraints = constraints
        return self

    def max_executions(self, max_executions: int) -> PermitBuilder:
        """Set maximum execution count."""
        self._max_executions = max_executions
        return self

    def valid_from_ms(self, valid_from_ms: int) -> PermitBuilder:
        """Set validity start time."""
        self._valid_from_ms = valid_from_ms
        return self

    def valid_until_ms(self, valid_until_ms: int) -> PermitBuilder:
        """Set validity end time."""
        self._valid_until_ms = valid_until_ms
        return self

    def evidence_hash(self, evidence_hash: str) -> PermitBuilder:
        """Set evidence hash."""
        self._evidence_hash = evidence_hash
        return self

    def proposal_hash(self, proposal_hash: str) -> PermitBuilder:
        """Set proposal hash."""
        self._proposal_hash = proposal_hash
        return self

    def nonce(self, nonce: str) -> PermitBuilder:
        """Set nonce (or generate if empty)."""
        self._nonce = nonce
        return self

    def build(self, keyring: dict[str, bytes], key_id: str) -> PermitToken:
        """
        Build and sign the permit token.

        Steps:
        1. Generate nonce if not set
        2. Create unsigned permit (empty permit_id and signature)
        3. Compute permit_id
        4. Sign permit with HMAC
        5. Return final signed permit

        Args:
            keyring: Map of key_id -> HMAC secret
            key_id: Which key to use for signing

        Returns:
            Fully constructed and signed PermitToken

        Raises:
            ValueError: If required fields missing or key_id not in keyring
        """
        # Generate nonce if not set
        if not self._nonce:
            self._nonce = generate_nonce()

        # Validate key_id
        if key_id not in keyring:
            raise ValueError(f"key_id '{key_id}' not in keyring")

        # Create unsigned permit
        unsigned = PermitToken(
            permit_id="",  # Will compute
            issuer=self._issuer,
            subject=self._subject,
            jurisdiction=self._jurisdiction,
            action=self._action,
            params=self._params,
            constraints=self._constraints,
            max_executions=self._max_executions,
            valid_from_ms=self._valid_from_ms,
            valid_until_ms=self._valid_until_ms,
            evidence_hash=self._evidence_hash,
            proposal_hash=self._proposal_hash,
            nonce=self._nonce,
            signature="",  # Will compute
            key_id=key_id,
        )

        # Compute permit_id
        permit_id = compute_permit_id(unsigned)
        with_id = replace(unsigned, permit_id=permit_id)

        # Sign permit
        signed = sign_permit(with_id, keyring[key_id], key_id)

        return signed
