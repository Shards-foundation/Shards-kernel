# Shards-Kernel Schemas

**Version:** 0.1.0  
**Classification:** Technical Reference  
**Last Updated:** January 2025

---

## 1. Overview

This document defines all data schemas used in Shards-Kernel. Schemas are the contracts between components.

---

## 2. Core Schemas

### 2.1 Request Schema

```python
@dataclass
class Request:
    """A request submitted to the kernel for arbitration."""
    
    # Identity
    request_id: str          # Unique identifier (UUID v4)
    
    # Actor
    actor: str               # Who is making the request
    
    # Intent
    intent: str              # Natural language description
    
    # Tool (optional)
    tool_call: Optional[ToolCall]  # Specific tool invocation
    
    # Evidence (optional)
    evidence: Optional[list[str]]  # Evidence IDs supporting request
    
    # Constraints (optional, for DualChannelKernel)
    constraints: Optional[dict]    # Scope, non_goals, success_criteria
    
    # Metadata
    ts_ms: int               # Request timestamp (milliseconds)
```

**Validation Rules:**

| Field | Rule |
|-------|------|
| request_id | Non-empty, unique |
| actor | Non-empty string |
| intent | Non-empty string (variant-dependent) |
| tool_call | Valid ToolCall if present |
| ts_ms | Positive integer |

### 2.2 ToolCall Schema

```python
@dataclass
class ToolCall:
    """A specific tool invocation within a request."""
    
    # Identity
    name: str                # Tool name (must be registered)
    
    # Parameters
    params: dict             # Tool-specific parameters
```

**Validation Rules:**

| Field | Rule |
|-------|------|
| name | Non-empty, registered tool |
| params | Valid dict |

### 2.3 Receipt Schema

```python
@dataclass
class Receipt:
    """The kernel's response to a request."""
    
    # Identity
    request_id: str          # Echoed from request
    
    # Status
    status: str              # ACCEPTED, REJECTED, FAILED
    
    # Decision
    decision: Decision       # ALLOW, DENY, HALT
    
    # State
    state_from: KernelState  # State before processing
    state_to: KernelState    # State after processing
    
    # Evidence
    evidence_hash: str       # Hash of audit entry
    
    # Result (optional)
    result: Optional[Any]    # Tool execution result
    
    # Error (optional)
    error: Optional[str]     # Error message if failed
    
    # Timing
    ts_ms: int               # Receipt timestamp
```

### 2.4 Decision Enum

```python
class Decision(Enum):
    """Possible decisions from the kernel."""
    
    ALLOW = "ALLOW"    # Request permitted
    DENY = "DENY"      # Request denied
    HALT = "HALT"      # Kernel halted
```

### 2.5 KernelState Enum

```python
class KernelState(Enum):
    """Possible states of the kernel."""
    
    BOOTING = "BOOTING"        # Initializing
    IDLE = "IDLE"              # Ready for requests
    VALIDATING = "VALIDATING"  # Checking request
    ARBITRATING = "ARBITRATING" # Evaluating policy
    EXECUTING = "EXECUTING"    # Running tool
    AUDITING = "AUDITING"      # Recording decision
    HALTED = "HALTED"          # Terminal state
```

---

## 3. Audit Schemas

### 3.1 AuditEntry Schema

```python
@dataclass
class AuditEntry:
    """A single entry in the audit ledger."""
    
    # Chain
    prev_hash: str           # Hash of previous entry
    entry_hash: str          # Hash of this entry
    
    # Request
    request_id: str          # Request that triggered entry
    actor: str               # Actor from request
    intent: str              # Intent from request
    
    # Decision
    decision: str            # ALLOW, DENY, HALT
    
    # State
    state_from: str          # State before
    state_to: str            # State after
    
    # Timing
    ts_ms: int               # Entry timestamp
    
    # Tool (optional)
    tool_name: Optional[str]     # Tool if executed
    params_hash: Optional[str]   # Hash of params
    
    # Evidence (optional)
    evidence_hash: Optional[str] # Hash of evidence
    
    # Error (optional)
    error: Optional[str]         # Error if failed
```

### 3.2 EvidenceBundle Schema

```python
@dataclass
class EvidenceBundle:
    """Exportable evidence package."""
    
    # Identity
    kernel_id: str           # Kernel that produced bundle
    variant: str             # Kernel variant
    
    # Ledger
    ledger_entries: list[dict]  # All audit entries
    
    # Integrity
    root_hash: str           # Hash of final entry
    
    # Timing
    exported_at_ms: int      # Export timestamp
```

---

## 4. Policy Schemas

### 4.1 JurisdictionPolicy Schema

```python
@dataclass
class JurisdictionPolicy:
    """Policy defining kernel jurisdiction."""
    
    # Actors
    allowed_actors: list[str]    # Permitted actors
    
    # Tools
    allowed_tools: list[str]     # Permitted tools
    
    # Options
    require_tool_call: bool      # Require explicit tool
    max_intent_length: int       # Intent size limit
    
    # Metadata
    policy_id: Optional[str]     # Policy identifier
    created_at_ms: Optional[int] # Creation timestamp
```

### 4.2 PolicyEvaluation Schema

```python
@dataclass
class PolicyEvaluation:
    """Result of policy evaluation."""
    
    # Decision
    allowed: bool            # Whether request is allowed
    
    # Details
    checks: list[dict]       # Individual check results
    
    # Reason
    reason: Optional[str]    # Denial reason if not allowed
```

---

## 5. Permit Schemas

### 5.1 PermitToken Schema

```python
@dataclass
class PermitToken:
    """Token authorizing worker execution."""
    
    # Identity
    permit_id: str           # Unique identifier
    
    # Scope
    proposal_hash: str       # Hash of approved proposal
    allowed_tool: str        # Tool permitted
    allowed_params_hash: str # Hash of permitted params
    
    # Constraints
    max_executions: int      # Execution limit
    expires_at_ms: int       # Expiration timestamp
    
    # Integrity
    signature: str           # HMAC signature
    
    # Metadata
    issued_at_ms: int        # Issue timestamp
    issued_by: str           # Issuing kernel ID
```

### 5.2 PermitVerification Schema

```python
@dataclass
class PermitVerification:
    """Result of permit verification."""
    
    # Status
    valid: bool              # Whether permit is valid
    
    # Checks
    signature_valid: bool    # Signature verification
    not_expired: bool        # Expiration check
    executions_remaining: int # Remaining executions
    
    # Error
    error: Optional[str]     # Error if invalid
```

---

## 6. Evidence Schemas

### 6.1 EvidencePacket Schema

```python
@dataclass
class EvidencePacket:
    """Observation from a sensor."""
    
    # Identity
    evidence_id: str         # Unique identifier
    packet_type: str         # Type of evidence
    
    # Source
    sensor_id: str           # Producing sensor
    sensor_type: str         # Sensor category
    
    # Timing
    observed_at_ms: int      # Observation time
    received_at_ms: int      # Receipt time
    
    # Content
    payload: dict            # Type-specific data
    payload_hash: str        # Hash of payload
    
    # Context
    context: dict            # Environmental context
    
    # Integrity
    sensor_signature: Optional[str]  # Sensor signature
```

### 6.2 EvidenceBinding Schema

```python
@dataclass
class EvidenceBinding:
    """Binding of evidence to proposal."""
    
    # Reference
    evidence_id: str         # Evidence packet ID
    
    # Type
    binding_type: str        # precondition, context, attestation
    
    # Requirements
    required: bool           # Must evidence exist
    freshness_ms: int        # Max age of evidence
```

---

## 7. Proposal Schemas

### 7.1 Proposal Schema

```python
@dataclass
class Proposal:
    """Structured request eliminating ambiguity."""
    
    # Identity
    proposal_id: str         # Unique identifier
    
    # Actor
    actor_id: str            # Requesting actor
    
    # Action
    action: ProposedAction   # What to do
    
    # Evidence
    evidence_bindings: list[EvidenceBinding]  # Supporting evidence
    
    # Constraints
    constraints: ProposalConstraints  # Boundaries
    
    # Timing
    submitted_at_ms: int     # Submission time
    expires_at_ms: int       # Expiration time
    
    # Integrity
    proposal_hash: str       # Hash of proposal
```

### 7.2 ProposedAction Schema

```python
@dataclass
class ProposedAction:
    """Specific action within proposal."""
    
    # Type
    action_type: str         # tool_call, approval, query
    
    # Tool (if tool_call)
    tool_name: Optional[str]
    tool_params: Optional[dict]
    
    # Expected outcome
    expected_outcome: str    # Description of expected result
    
    # Rollback
    rollback_action: Optional[str]  # How to undo
```

### 7.3 ProposalConstraints Schema

```python
@dataclass
class ProposalConstraints:
    """Boundaries for proposal execution."""
    
    # Scope
    scope: str               # What is in scope
    
    # Non-goals
    non_goals: list[str]     # What is explicitly out of scope
    
    # Success criteria
    success_criteria: list[str]  # How to measure success
    
    # Limits
    max_retries: int         # Retry limit
    timeout_ms: int          # Execution timeout
```

---

## 8. Schema Validation

### 8.1 Validation Functions

```python
def validate_request(request: Request) -> tuple[bool, list[str]]:
    """Validate request against schema."""
    errors = []
    
    if not request.request_id:
        errors.append("request_id is required")
    
    if not request.actor:
        errors.append("actor is required")
    
    if not request.intent:
        errors.append("intent is required")
    
    if request.tool_call:
        tool_valid, tool_errors = validate_tool_call(request.tool_call)
        errors.extend(tool_errors)
    
    return len(errors) == 0, errors

def validate_tool_call(tool_call: ToolCall) -> tuple[bool, list[str]]:
    """Validate tool call against schema."""
    errors = []
    
    if not tool_call.name:
        errors.append("tool_call.name is required")
    
    if tool_call.params is None:
        errors.append("tool_call.params is required")
    
    return len(errors) == 0, errors
```

### 8.2 Schema Versioning

| Schema | Version | Status |
|--------|---------|--------|
| Request | 1.0 | Stable |
| ToolCall | 1.0 | Stable |
| Receipt | 1.0 | Stable |
| AuditEntry | 1.0 | Stable |
| EvidenceBundle | 1.0 | Stable |
| JurisdictionPolicy | 1.0 | Stable |
| PermitToken | 0.1 | Draft |
| EvidencePacket | 0.1 | Draft |
| Proposal | 0.1 | Draft |

---

## 9. Schema Evolution

### 9.1 Compatibility Rules

| Change Type | Backward Compatible |
|-------------|---------------------|
| Add optional field | ✅ Yes |
| Add required field | ❌ No |
| Remove field | ❌ No |
| Rename field | ❌ No |
| Change field type | ❌ No |
| Add enum value | ✅ Yes |
| Remove enum value | ❌ No |

### 9.2 Migration Strategy

1. **Minor version:** Add optional fields only
2. **Major version:** Breaking changes allowed
3. **Deprecation:** Mark field deprecated, remove in next major
4. **Migration:** Provide migration scripts for major versions
