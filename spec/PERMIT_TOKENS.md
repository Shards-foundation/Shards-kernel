# PERMIT_TOKENS.md

**Status:** Draft
**Version:** 0.2.0-dev
**Normative:** Yes
**Last Updated:** 2026-01-14

---

## 1. PURPOSE

Permit tokens are cryptographically signed capability objects that bind:

- **WHO** authorized (issuer identity)
- **WHAT** is authorized (tool, parameters, constraints)
- **WHEN** it is valid (time/step/state window)
- **WHY** it was authorized (proposal/evidence linkage)
- **HOW** it's verified (deterministic, fail-closed)

Permits are the enforcement primitive that translates governance decisions into execution constraints.

---

## 2. THREAT MODEL

### 2.1 Adversaries

1. **Malicious Worker** - Attempts to forge permits, escalate privileges, or execute unauthorized actions
2. **Compromised Cockpit** - Issues overly broad permits or backdated permits
3. **Replay Attacker** - Reuses valid permits beyond their intended scope
4. **Tampering Adversary** - Modifies permit fields to expand authorization
5. **Time Manipulation** - Attempts to exploit window boundaries or clock skew

### 2.2 Assets Protected

- **Jurisdiction integrity** - Workers execute only within authorized scope
- **Audit completeness** - Every execution traces to a permit → proposal → evidence chain
- **Replay resistance** - Each permit is single-use (or bounded-use)
- **Constraint enforcement** - Parameters, resource limits, and allowlists are enforced

### 2.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│ COCKPIT (Operator Interface)                        │
│ - Has signing key (HMAC secret)                     │
│ - Issues permits after operator approval            │
│ - Trusted to enforce operator intent                │
└─────────────────┬───────────────────────────────────┘
                  │ Permit Token (signed)
                  ↓
┌─────────────────────────────────────────────────────┐
│ KERNEL (Governance Plane)                           │
│ - Has verification key (same HMAC secret)           │
│ - Verifies permit before allowing execution         │
│ - Maintains nonce registry (replay protection)      │
│ - NEVER has network access or LLM calls             │
└─────────────────┬───────────────────────────────────┘
                  │ Execution if permit valid
                  ↓
┌─────────────────────────────────────────────────────┐
│ WORKER (Execution Plane)                            │
│ - Receives permit token (opaque blob)               │
│ - Cannot forge, modify, or verify permits           │
│ - Executes only if kernel accepts permit            │
└─────────────────────────────────────────────────────┘
```

**Key property:** Worker never sees signing key; cockpit and kernel share HMAC secret.

---

## 3. PERMIT TOKEN STRUCTURE

### 3.1 Required Fields

```python
@dataclass(frozen=True)
class PermitToken:
    """
    Immutable capability token authorizing a specific action.

    Invariants:
    - All fields are immutable (frozen dataclass)
    - permit_id is deterministic (content hash of canonical form)
    - Signature is HMAC-SHA256 over canonical encoding
    - Missing fields cause verification to fail
    """

    # Identity
    permit_id: str          # SHA-256 hash of canonical permit (excludes signature)
    issuer: str             # Cockpit principal who authorized this permit
    subject: str            # Worker identity authorized to execute

    # Authorization scope
    jurisdiction: str       # Explicit jurisdiction this permit operates within
    action: str             # Tool name or worker action being authorized
    params: dict[str, Any]  # Exact parameters allowed (must match request)

    # Constraints
    constraints: dict[str, Any]  # Resource limits, allowlists, parameter bounds
    max_executions: int          # How many times this permit can be used (1 = single-use)

    # Validity window
    valid_from_ms: int      # Monotonic timestamp (milliseconds) when permit becomes valid
    valid_until_ms: int     # Monotonic timestamp when permit expires

    # Audit linkage
    evidence_hash: str      # SHA-256 hash of evidence packet that justified this permit
    proposal_hash: str      # SHA-256 hash of proposal that requested this action

    # Replay protection
    nonce: str              # Unique value (UUID4 or hash-derived) for replay detection

    # Cryptographic binding
    signature: str          # HMAC-SHA256(key, canonical_permit_bytes) in hex
    key_id: str             # Identifier for which HMAC key was used (for rotation)
```

### 3.2 Field Semantics

| Field | Type | Constraints | Semantics |
|-------|------|-------------|-----------|
| `permit_id` | str | 64-char hex (SHA-256) | Stable identifier; content hash of canonical permit |
| `issuer` | str | Non-empty, max 256 chars | Cockpit principal or operator identity |
| `subject` | str | Non-empty, max 256 chars | Worker identity; must match execution context |
| `jurisdiction` | str | Non-empty, max 256 chars | Must match kernel's active jurisdiction policy |
| `action` | str | Non-empty, max 256 chars | Tool name; must be on allowlist |
| `params` | dict | Max 64KB serialized | Exact parameters including all keys, values and JSON types; omissions deny |
| `constraints` | dict | Max 64KB serialized | Bounds: `max_time_ms`, `max_memory_mb`, `allowed_domains`, etc. |
| `max_executions` | int | ≥1 | Single-use = 1; multi-use = N; unlimited = -1 (discouraged) |
| `valid_from_ms` | int | ≥0 | Monotonic time; permit invalid before this |
| `valid_until_ms` | int | > valid_from_ms | Monotonic time; permit invalid after this |
| `evidence_hash` | str | 64-char hex or empty | Hash of evidence packet; may be empty for low-risk actions |
| `proposal_hash` | str | 64-char hex | Hash of proposal that initiated this workflow |
| `nonce` | str | 32-char hex (min) | Random UUID or derived hash; must be unique per issuer+subject |
| `signature` | str | 64-char hex (HMAC-SHA256) | Cryptographic signature over canonical permit |
| `key_id` | str | Non-empty, max 64 chars | Key identifier; e.g., "kernel-v1", "cockpit-2026-01" |

---

## 4. CANONICAL SERIALIZATION

### 4.1 Encoding Rules

To ensure deterministic hashing and verification:

1. **Field ordering:** Alphabetical by field name
2. **Dict ordering:** Keys sorted alphabetically at all nesting levels
3. **No floating point:** Use integers (milliseconds, not seconds)
4. **UTF-8 encoding:** All strings as UTF-8 bytes
5. **No whitespace:** Compact JSON (no spaces, newlines)
6. **Null handling:** Empty strings `""`, not `null`
7. **Signature exclusion:** The `signature` field is NOT included in canonical form (it signs everything else)

### 4.2 Canonical Encoding Function

```python
def canonical_permit_bytes(permit: PermitToken) -> bytes:
    """
    Produce deterministic byte representation of permit (excluding signature).

    Returns: UTF-8 encoded compact JSON with sorted keys.
    """
    data = {
        "action": permit.action,
        "constraints": _sort_dict_recursive(permit.constraints),
        "evidence_hash": permit.evidence_hash,
        "issuer": permit.issuer,
        "jurisdiction": permit.jurisdiction,
        "key_id": permit.key_id,
        "max_executions": permit.max_executions,
        "nonce": permit.nonce,
        "params": _sort_dict_recursive(permit.params),
        "permit_id": permit.permit_id,
        "proposal_hash": permit.proposal_hash,
        "subject": permit.subject,
        "valid_from_ms": permit.valid_from_ms,
        "valid_until_ms": permit.valid_until_ms,
    }
    # Note: 'signature' deliberately excluded

    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
```

### 4.3 Permit ID Computation

```python
permit_id = sha256(canonical_permit_bytes(permit_without_id_and_sig)).hexdigest()
```

**Bootstrapping:** When creating a new permit, `permit_id` and `signature` are initially empty, then computed:

1. Set `permit_id = ""` and `signature = ""`
2. Compute `canonical_bytes = canonical_permit_bytes(permit)`
3. Compute `permit_id = sha256(canonical_bytes).hexdigest()`
4. Update permit with `permit_id`
5. Recompute `canonical_bytes` with real `permit_id`
6. Compute `signature = hmac.new(key, canonical_bytes, sha256).hexdigest()`
7. Final permit has both `permit_id` and `signature`

---

## 5. CRYPTOGRAPHIC OPERATIONS

### 5.1 HMAC-Based Signing

**Why HMAC instead of RSA/ECDSA?**

- Constraint: Standard library only (no external crypto dependencies)
- Python `hmac` module is stdlib
- HMAC-SHA256 provides:
  - Authentication (only keyholder can produce valid signature)
  - Integrity (any modification invalidates signature)
  - Determinism (same input + key = same signature)

**Key management:**

- Kernel and cockpit share a secret HMAC key (256 bits recommended)
- Key distribution is out-of-band (environment variable, config file, HSM for production)
- Worker NEVER receives the key

### 5.2 Signing Algorithm

```python
def sign_permit(permit: PermitToken, key: bytes, key_id: str) -> PermitToken:
    """
    Sign a permit token with HMAC-SHA256.

    Args:
        permit: Permit with permit_id computed but signature empty
        key: HMAC secret key (32 bytes recommended)
        key_id: Key identifier for rotation support

    Returns:
        New permit with signature field populated
    """
    canonical = canonical_permit_bytes(permit)
    sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    return dataclasses.replace(permit, signature=sig, key_id=key_id)
```

### 5.3 Verification Algorithm (Fail-Closed)

```python
def verify_permit(permit: PermitToken, keyring: dict[str, bytes]) -> PermitVerificationResult:
    """
    Verify permit signature and constraints.

    Fail-closed: ANY uncertainty or violation returns DENY.

    Returns:
        PermitVerificationResult with status (ALLOW/DENY) and reason codes
    """
    reasons = []

    # 1. Key ID check
    if permit.key_id not in keyring:
        return PermitVerificationResult(status=ReceiptStatus.DENY,
                                        reasons=["UNKNOWN_KEY_ID"])

    key = keyring[permit.key_id]

    # 2. Signature verification
    canonical = canonical_permit_bytes(permit)
    expected_sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(permit.signature, expected_sig):
        return PermitVerificationResult(status=ReceiptStatus.DENY,
                                        reasons=["SIGNATURE_INVALID"])

    # 3. Permit ID verification
    permit_without_sig = dataclasses.replace(permit, signature="", permit_id="")
    canonical_for_id = canonical_permit_bytes(permit_without_sig)
    expected_id = hashlib.sha256(canonical_for_id).hexdigest()

    if permit.permit_id != expected_id:
        return PermitVerificationResult(status=ReceiptStatus.DENY,
                                        reasons=["PERMIT_ID_MISMATCH"])

    # 4-10: Additional checks (see Section 6)

    return PermitVerificationResult(status=ReceiptStatus.ALLOW, reasons=[])
```

**Security property:** Uses `hmac.compare_digest()` for constant-time comparison (timing attack resistance).

---

## 6. VERIFICATION PIPELINE (Fail-Closed)

The kernel MUST verify all constraints before allowing execution. Any failure = DENY.

### 6.1 Verification Checklist

| # | Check | Denial Reason Code | Description |
|---|-------|-------------------|-------------|
| 1 | Key ID known | `UNKNOWN_KEY_ID` | `key_id` not in kernel's keyring |
| 2 | Signature valid | `SIGNATURE_INVALID` | HMAC mismatch |
| 3 | Permit ID valid | `PERMIT_ID_MISMATCH` | Hash doesn't match canonical form |
| 4 | Time window | `EXPIRED`, `NOT_YET_VALID` | Current time outside [valid_from, valid_until] |
| 5 | Jurisdiction match | `JURISDICTION_MISMATCH` | Permit jurisdiction ≠ kernel jurisdiction |
| 6 | Action allowed | `ACTION_NOT_ALLOWED` | Action not on allowlist for this jurisdiction |
| 7 | Subject match | `SUBJECT_MISMATCH` | Permit subject ≠ request actor |
| 8 | Params match | `PARAMS_MISMATCH` | Any mismatch in the effective tool argument mapping, including omitted, extra, changed or type-aliased values; compare against one private snapshot of the verified signed permit |
| 9 | Nonce fresh | `REPLAY_DETECTED` | Nonce already used |
| 10 | Execution count | `MAX_EXECUTIONS_EXCEEDED` | Permit already used max_executions times |
| 11 | Constraints satisfied | `CONSTRAINT_VIOLATION` | Resource limits, allowlists, bounds violated |

### 6.2 Fail-Closed Guarantee

```
IF (any check fails) THEN
    status = DENY
    audit_entry.decision = DENY
    audit_entry.denial_reasons = [reason_codes...]
    return DENY
ELSE
    status = ALLOW
    audit_entry.decision = ALLOW
    audit_entry.permit_digest = permit.permit_id
    return ALLOW
```

**No partial acceptance:** Either all checks pass (ALLOW) or any fails (DENY).

---

## 7. REPLAY PROTECTION

### 7.1 Nonce Registry

The kernel maintains an append-only nonce registry to detect replays:

```python
@dataclass(frozen=True)
class NonceRecord:
    nonce: str              # The nonce value
    issuer: str             # Who issued the permit with this nonce
    subject: str            # Who was authorized
    first_seen_ms: int      # When first used
    use_count: int          # How many times seen
    permit_id: str          # Which permit used this nonce
```

**Storage:** In-memory dict for performance; persisted in audit ledger for reconstruction.

### 7.2 Replay Detection Algorithm

```python
def check_nonce(nonce: str, issuer: str, subject: str, max_executions: int) -> bool:
    """
    Check if nonce is fresh (not replayed).

    Returns:
        True if nonce is fresh (allow execution)
        False if replay detected (deny execution)
    """
    key = (nonce, issuer, subject)

    if key not in nonce_registry:
        # First use: record it
        nonce_registry[key] = NonceRecord(nonce, issuer, subject,
                                          current_time_ms(), 1, permit_id)
        return True  # Fresh

    record = nonce_registry[key]

    if record.use_count >= max_executions:
        return False  # Replay: exceeded max uses

    # Increment use count
    nonce_registry[key] = dataclasses.replace(record, use_count=record.use_count + 1)
    return True  # Still within allowed uses
```

### 7.3 Nonce Generation (Cockpit Side)

```python
def generate_nonce() -> str:
    """Generate cryptographically random nonce."""
    return uuid.uuid4().hex  # 32 hex chars
```

**Alternative (deterministic nonces):** For testing or replay scenarios:

```python
def deterministic_nonce(proposal_hash: str, sequence: int) -> str:
    """Derive nonce from proposal hash + sequence number."""
    data = f"{proposal_hash}:{sequence}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()[:32]
```

### 7.4 Nonce Semantics

**Critical invariant:** Nonces are **per-permit-instance**, NOT per-use.

A single permit with `max_executions=N` uses the **same nonce** for all N executions. The nonce uniquely identifies the permit instance, and the registry tracks `use_count` to enforce the execution limit.

**Why this matters:**

1. **Ledger-backed reconstruction:** After kernel restart, the nonce registry is rebuilt by replaying audit entries. Each ALLOW entry with the same nonce increments `use_count`.

2. **Multi-use permits:** A permit with `max_executions=3` can be used 3 times with the same nonce. The 4th attempt is rejected as `REPLAY_DETECTED` because `use_count=3 >= max_executions=3`.

3. **Cross-restart invariant:** Total accepted executions ≤ max_executions, even across restarts.

**Reconstruction algorithm:**

```python
def rebuild_nonce_registry_from_ledger(ledger_entries: list[AuditEntry]) -> NonceRegistry:
    """
    Rebuild nonce registry from audit ledger entries.

    Processes entries in deterministic order (by ledger_seq) to ensure
    consistent use_count reconstruction.
    """
    registry = NonceRegistry()

    # Sort by ledger_seq for deterministic ordering (timestamp ties are broken)
    for entry in sorted(ledger_entries, key=lambda e: e.ledger_seq):
        if entry.permit_verification == "ALLOW" and entry.permit_nonce:
            # Reconstruct nonce usage by calling check_and_record
            # This increments use_count for each ALLOW entry
            registry.check_and_record(
                nonce=entry.permit_nonce,
                issuer=entry.permit_issuer,
                subject=entry.permit_subject,
                permit_id=entry.permit_digest,
                max_executions=entry.permit_max_executions,
                current_time_ms=entry.ts_ms,
            )

    return registry
```

**Storage requirements:**

Audit entries must persist the following fields for nonce reconstruction:
- `permit_nonce`: The nonce value
- `permit_issuer`: Issuer identity (part of registry key)
- `permit_subject`: Subject identity (part of registry key)
- `permit_max_executions`: Maximum allowed uses
- `permit_verification`: "ALLOW" or "DENY" (only ALLOW entries count)
- `ledger_seq`: Monotonic sequence number for deterministic ordering

**Deterministic ordering:**

Entries are sorted by `ledger_seq` (not `ts_ms`) to prevent non-determinism when multiple entries have identical timestamps. This ensures reconstruction produces identical nonce registries across restarts.

---

## 8. CONSTRAINT ENFORCEMENT

### 8.1 Constraint Schema

The implementation currently enforces `forbidden_params` and
`require_evidence`. Unsupported constraints, including `max_time_ms`,
`max_memory_mb`, and `allowed_domains`, are rejected before execution.
The following illustrates possible future constraint fields, not a guarantee
that each field is implemented:

```python
constraints = {
    "max_time_ms": 5000,              # Max execution time
    "max_memory_mb": 512,             # Max memory usage
    "allowed_domains": ["api.example.com"],  # Network allowlist
    "forbidden_params": ["--unsafe"],  # Parameter blocklist
    "require_evidence": True,          # Must have evidence_hash
    "risk_class": "low",               # Risk classification
}
```

### 8.2 Constraint Validation

The following is illustrative pseudocode for future mechanisms. In particular,
a post-execution measurement cannot enforce `max_time_ms`; synchronous tools
with this constraint are denied until a suitable isolation mechanism exists.

```python
def validate_constraints(permit: PermitToken, request: KernelRequest) -> list[str]:
    """
    Validate request against permit constraints.

    Returns:
        List of violation reason codes (empty = all satisfied)
    """
    violations = []

    # Example: Check max_time_ms
    if "max_time_ms" in permit.constraints:
        if request.estimated_time_ms > permit.constraints["max_time_ms"]:
            violations.append("TIME_LIMIT_EXCEEDED")

    # Example: Check allowed_domains
    if "allowed_domains" in permit.constraints:
        if request.target_domain not in permit.constraints["allowed_domains"]:
            violations.append("DOMAIN_NOT_ALLOWED")

    # Example: Check forbidden params
    if "forbidden_params" in permit.constraints:
        for forbidden in permit.constraints["forbidden_params"]:
            if forbidden in request.params:
                violations.append("FORBIDDEN_PARAM_DETECTED")

    return violations
```

---

## 9. AUDIT LINKAGE

### 9.1 Audit Entry Extension

When a permit is verified, the audit entry MUST include:

```python
@dataclass(frozen=True)
class AuditEntry:
    # ... existing fields ...

    # Permit-related fields (added in v0.2.0)
    permit_digest: str | None       # permit_id if permit was used
    permit_verification: str        # "ALLOW" | "DENY"
    permit_denial_reasons: list[str]  # Reason codes if denied
    proposal_hash: str | None       # From permit.proposal_hash
    evidence_hash: str | None       # From permit.evidence_hash
```

### 9.2 Evidence Chain Traceability

For any execution, an auditor can trace:

```
Execution (audit entry)
    → permit_digest
    → PermitToken
    → proposal_hash
    → Proposal
    → evidence_hash
    → Evidence Packet
```

This provides complete lineage from operator intent to execution result.

---

## 10. KEY ROTATION

### 10.1 Keyring Management

The kernel maintains a keyring of active HMAC keys:

```python
keyring: dict[str, bytes] = {
    "kernel-v1": bytes.fromhex("a1b2c3..."),  # Primary key
    "kernel-v0": bytes.fromhex("d4e5f6..."),  # Deprecated key (still verify)
}
```

### 10.2 Rotation Protocol

1. **Add new key:** Add to keyring with new `key_id`
2. **Dual signing period:** Cockpit signs with new key; kernel accepts both old and new
3. **Deprecate old key:** After grace period, remove old key from keyring
4. **Audit:** Every key addition/removal logged in audit trail

### 10.3 Key Denial

If `key_id` not in keyring:

```
status = DENY
reason = "UNKNOWN_KEY_ID"
```

This allows graceful key rotation without breaking existing permits during transition.

---

## 11. INVARIANT PRESERVATION

### 11.1 How Permits Preserve Core Invariants

| Invariant | Permit Mechanism |
|-----------|------------------|
| INV-STATE | Permits verified during VALIDATING/ARBITRATING transitions |
| INV-TRANSITION | Verification logic called from transition functions |
| INV-JURISDICTION | Permit jurisdiction must match kernel policy |
| INV-AUDIT | Every verification (allow/deny) emits audit entry |
| INV-HASH-CHAIN | Permit verification results chained into ledger |
| INV-FAIL-CLOSED | Any verification failure → DENY; no partial acceptance |
| INV-DETERMINISM | HMAC and hashing are deterministic; same inputs = same outputs |
| INV-HALT | Verification errors can trigger HALT in StrictKernel |
| INV-EVIDENCE | Permits link to evidence_hash for traceability |
| INV-NO-IMPLICIT-ALLOW | Permit required for execution; missing permit = deny |

---

## 12. ATTACK SURFACE ANALYSIS

### 12.1 Known Attack Vectors

| Attack | Mitigation |
|--------|-----------|
| **Permit forgery** | HMAC signature; worker has no signing key |
| **Permit tampering** | Any field change invalidates HMAC |
| **Replay attacks** | Nonce registry; single-use or bounded-use |
| **Time window exploitation** | Monotonic clock; strict boundary checks |
| **Privilege escalation** | Params must match exactly; missing keys and handler-default substitutions deny |
| **Constraint bypass** | All constraints validated before execution |
| **Key compromise** | Key rotation support; revoke old keys |
| **Nonce collision** | UUID4 has ~2^122 space; cryptographically unlikely |

### 12.2 Residual Risks

1. **HMAC key compromise:** If attacker gets signing key, they can forge permits
   - **Mitigation:** Secure key storage (env vars, secrets manager, HSM)
   - **Detection:** Audit trail shows unauthorized permits

2. **Cockpit compromise:** Malicious cockpit can issue overly broad permits
   - **Mitigation:** Operator approval workflows; permit review
   - **Detection:** Audit permits for anomalies

3. **Clock skew:** If kernel clock diverges, time windows may be exploited
   - **Mitigation:** Use virtual monotonic clock; NTP sync
   - **Detection:** Clock drift alerts

---

## 13. STDLIB-ONLY IMPLEMENTATION

All cryptographic operations use Python standard library:

- `hashlib.sha256()` - Hashing
- `hmac.new(key, msg, sha256)` - HMAC signing
- `hmac.compare_digest()` - Constant-time comparison
- `json.dumps(sort_keys=True)` - Canonical serialization
- `uuid.uuid4()` - Nonce generation
- `dataclasses.dataclass(frozen=True)` - Immutable types

**No external dependencies required.**

---

## 14. ACCEPTANCE CRITERIA

### 14.1 Determinism

✅ **AC-1:** Identical token bytes verify identically across runs.

**Test:** Serialize permit → verify → serialize again → verify; all results identical.

### 14.2 Tamper Evidence

✅ **AC-2:** Any change to token fields invalidates signature.

**Test:** Change any field by 1 character → verification fails with `SIGNATURE_INVALID`.

### 14.3 Replay Safety

✅ **AC-3:** Reusing same token fails after max_executions exceeded.

**Test:** Use single-use permit twice → second use denied with `REPLAY_DETECTED`.

### 14.4 Constraint Enforcement

✅ **AC-4:** Permit authorizes strict subset of actions; divergence denies.

**Test:** Permit allows `{"action": "read", "path": "/foo"}`; request `{"action": "write"}` → denied with `PARAMS_MISMATCH`.

### 14.5 Ledger Evidence

✅ **AC-5:** For any execution, trace from entry → permit → proposal → evidence.

**Test:** Export ledger → find entry → extract permit_digest → find permit → extract proposal_hash → verify chain complete.

---

## 15. NEGATIVE TEST REQUIREMENTS

Implement at least **25 negative tests** covering:

1. `UNKNOWN_KEY_ID` - Key not in keyring
2. `SIGNATURE_INVALID` - Tampered signature
3. `PERMIT_ID_MISMATCH` - Hash doesn't match canonical
4. `EXPIRED` - Current time > valid_until
5. `NOT_YET_VALID` - Current time < valid_from
6. `JURISDICTION_MISMATCH` - Wrong jurisdiction
7. `ACTION_NOT_ALLOWED` - Tool not on allowlist
8. `SUBJECT_MISMATCH` - Wrong worker identity
9. `PARAMS_MISMATCH` - Request params exceed permit
10. `REPLAY_DETECTED` - Nonce reused
11. `MAX_EXECUTIONS_EXCEEDED` - Used too many times
12. `CONSTRAINT_VIOLATION` - Resource limit exceeded
13. Missing `issuer` field
14. Missing `subject` field
15. Missing `jurisdiction` field
16. Missing `action` field
17. Missing `nonce` field
18. Missing `signature` field
19. Negative `max_executions`
20. `valid_until_ms < valid_from_ms`
21. Non-hex signature
22. Wrong signature length
23. Empty `permit_id`
24. Non-dict `params`
25. Non-dict `constraints`

---

## 16. FUTURE EXTENSIONS

### 16.1 Multi-Signature Permits

**Idea:** Require N-of-M signatures (e.g., 2 operators must approve).

**Implementation:** Replace single `signature` field with:

```python
signatures: list[tuple[str, str]]  # [(key_id, signature), ...]
required_signatures: int            # Minimum N
```

### 16.2 Conditional Permits

**Idea:** Permit valid only if certain conditions hold.

**Implementation:** Add `conditions` dict:

```python
conditions: dict[str, Any] = {
    "state_hash_must_be": "abc123...",  # Kernel state must match
    "ledger_size_max": 1000,            # Ledger must be below size
}
```

### 16.3 Delegation

**Idea:** Permit holder can issue sub-permits with reduced scope.

**Implementation:** Add `delegated_from` field pointing to parent permit.

---

## 17. REFERENCES

- **SPEC.md** - Core kernel specification
- **AUDIT.md** - Audit ledger structure
- **ERROR_MODEL.md** - Fail-closed semantics
- **JURISDICTION.md** - Policy enforcement
- **PROPOSAL.md** - Proposal schema (to be implemented)
- **EVIDENCE.md** - Evidence packet structure

---

## 18. CHANGELOG

| Version | Date | Changes |
|---------|------|---------|
| 0.2.0-dev | 2026-01-14 | Initial permit token specification |

---

**END OF SPECIFICATION**
