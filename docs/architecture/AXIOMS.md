# Shards-Kernel Axioms

**Version:** 0.1.0  
**Classification:** Foundational  
**Last Updated:** January 2025

---

## 1. Overview

Axioms are self-evident truths that form the foundation of Shards-Kernel. They are not derived from other principles; they are the principles from which everything else derives.

---

## 2. Core Axioms

### Axiom 1: Determinism

> **Given identical inputs, the kernel MUST produce identical outputs.**

**Implications:**
- No random number generation in decision path
- No external state queries during arbitration
- No time-dependent logic in policy evaluation
- Reproducible decisions enable verification

**Formal Statement:**
```
∀ input ∈ Requests, ∀ state ∈ KernelState:
  decide(input, state) = decide(input, state)
```

---

### Axiom 2: Fail-Closed

> **In the absence of explicit permission, the answer is NO.**

**Implications:**
- Default decision is DENY
- Ambiguity results in DENY
- Missing evidence results in DENY
- Unknown actors result in DENY
- Unknown tools result in DENY

**Formal Statement:**
```
∀ request ∈ Requests:
  ¬explicitly_allowed(request) → decision(request) = DENY
```

---

### Axiom 3: Auditability

> **Every decision MUST be recorded before it takes effect.**

**Implications:**
- Audit entry precedes state transition
- No decision without evidence
- Evidence is immutable once recorded
- Evidence is exportable for external verification

**Formal Statement:**
```
∀ transition ∈ Transitions:
  audit_entry_created(transition) ∧ 
  timestamp(audit_entry) < timestamp(transition_complete)
```

---

### Axiom 4: Separation of Concerns

> **Each component has exactly one job.**

**Implications:**
- Kernel decides, does not execute
- Workers execute, do not decide
- Sensors observe, do not act
- Cockpit displays, does not bypass

**Formal Statement:**
```
∀ component ∈ System:
  |responsibilities(component)| = 1
```

---

### Axiom 5: Explicit State

> **The kernel is always in exactly one known state.**

**Implications:**
- State is enumerable
- Transitions are explicit
- No implicit state changes
- State is observable

**Formal Statement:**
```
∀ t ∈ Time:
  ∃! state ∈ KernelState: kernel_state(t) = state
```

---

### Axiom 6: Hash Chain Integrity

> **Each audit entry cryptographically commits to all previous entries.**

**Implications:**
- Tampering is detectable
- Order is preserved
- History is immutable
- Verification is external

**Formal Statement:**
```
∀ entry[n] ∈ Ledger:
  entry[n].prev_hash = hash(entry[n-1])
```

---

### Axiom 7: Halt Authority

> **The kernel can always be stopped.**

**Implications:**
- Halt is always available
- Halt is immediate
- Halt is irrevocable (until restart)
- No operation can prevent halt

**Formal Statement:**
```
∀ state ∈ KernelState \ {HALTED}:
  can_transition(state, HALTED) = true
```

---

### Axiom 8: Jurisdiction Primacy

> **No action occurs outside defined jurisdiction.**

**Implications:**
- Policy is checked before execution
- Unknown actors are denied
- Unknown tools are denied
- Scope is explicit

**Formal Statement:**
```
∀ action ∈ Actions:
  executed(action) → within_jurisdiction(action)
```

---

### Axiom 9: Evidence Sufficiency

> **Decisions are based solely on available evidence.**

**Implications:**
- No hidden inputs
- No external queries during decision
- Evidence is the complete context
- Missing evidence is explicit

**Formal Statement:**
```
∀ decision ∈ Decisions:
  decision = f(evidence) where f is pure
```

---

### Axiom 10: Permit Requirement

> **Workers execute only with valid permits.**

**Implications:**
- No implicit authorization
- Permits are verifiable
- Permits are scoped
- Permits expire

**Formal Statement:**
```
∀ execution ∈ Executions:
  executed(execution) → valid_permit(execution.permit)
```

---

## 3. Derived Principles

### From Axiom 1 (Determinism)

| Principle | Derivation |
|-----------|------------|
| Reproducibility | Same inputs → same outputs → reproducible |
| Testability | Deterministic → predictable → testable |
| Verifiability | Reproducible → externally verifiable |

### From Axiom 2 (Fail-Closed)

| Principle | Derivation |
|-----------|------------|
| Safety by default | No permission → deny → safe |
| Explicit trust | Must explicitly allow → trust is explicit |
| Conservative operation | Deny on uncertainty → conservative |

### From Axiom 3 (Auditability)

| Principle | Derivation |
|-----------|------------|
| Accountability | Recorded → attributable → accountable |
| Transparency | Exportable → inspectable → transparent |
| Compliance | Auditable → demonstrable → compliant |

### From Axiom 4 (Separation)

| Principle | Derivation |
|-----------|------------|
| Modularity | One job → focused → modular |
| Testability | Isolated → independent → testable |
| Security | Separated → contained → secure |

---

## 4. Axiom Violations

### What Constitutes a Violation

| Axiom | Violation Example |
|-------|-------------------|
| Determinism | Random selection in policy |
| Fail-Closed | Default allow for unknown |
| Auditability | Decision without entry |
| Separation | Kernel making API calls |
| Explicit State | Undefined state value |
| Hash Chain | Missing prev_hash |
| Halt Authority | Blocked halt command |
| Jurisdiction | Execution without check |
| Evidence Sufficiency | External query in decision |
| Permit Requirement | Execution without permit |

### Violation Response

1. **Detection:** Automated invariant checks
2. **Logging:** Record violation details
3. **Halt:** Stop kernel operation
4. **Alert:** Notify operators
5. **Investigation:** Root cause analysis
6. **Remediation:** Fix and verify

---

## 5. Axiom Testing

### Test Strategy

```python
# Axiom 1: Determinism
def test_determinism():
    kernel = StrictKernel()
    request = create_test_request()
    
    result1 = kernel.submit(request)
    kernel.reset()
    result2 = kernel.submit(request)
    
    assert result1.decision == result2.decision
    assert result1.evidence_hash == result2.evidence_hash

# Axiom 2: Fail-Closed
def test_fail_closed():
    kernel = StrictKernel(policy=empty_policy())
    request = create_test_request()
    
    result = kernel.submit(request)
    
    assert result.decision == Decision.DENY

# Axiom 3: Auditability
def test_auditability():
    kernel = StrictKernel()
    request = create_test_request()
    
    result = kernel.submit(request)
    evidence = kernel.export_evidence()
    
    assert len(evidence["ledger_entries"]) > 0
    assert evidence["ledger_entries"][-1]["request_id"] == request.request_id

# Axiom 6: Hash Chain
def test_hash_chain():
    kernel = StrictKernel()
    
    for i in range(5):
        kernel.submit(create_test_request(f"req-{i}"))
    
    evidence = kernel.export_evidence()
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    assert is_valid
    assert len(errors) == 0

# Axiom 7: Halt Authority
def test_halt_authority():
    kernel = StrictKernel()
    
    # Should be able to halt from any non-terminal state
    kernel.halt()
    
    assert kernel.state == KernelState.HALTED
```

---

## 6. Axiom Preservation

### During Development

| Practice | Axiom Protected |
|----------|-----------------|
| Pure functions | Determinism |
| Default deny | Fail-Closed |
| Audit-first writes | Auditability |
| Single responsibility | Separation |
| Enum states | Explicit State |
| Immutable entries | Hash Chain |
| Halt always valid | Halt Authority |
| Policy-first checks | Jurisdiction |
| No external calls | Evidence Sufficiency |
| Permit verification | Permit Requirement |

### During Operation

| Practice | Axiom Protected |
|----------|-----------------|
| Reproducibility testing | Determinism |
| Deny rate monitoring | Fail-Closed |
| Ledger verification | Auditability, Hash Chain |
| Component isolation | Separation |
| State monitoring | Explicit State |
| Halt testing | Halt Authority |
| Policy auditing | Jurisdiction |
| Evidence review | Evidence Sufficiency |
| Permit logging | Permit Requirement |

---

## 7. Axiom Evolution

### Immutable Axioms

These axioms MUST NOT change:

1. Determinism
2. Fail-Closed
3. Auditability
4. Hash Chain Integrity
5. Halt Authority

### Refinable Axioms

These axioms MAY be refined (not weakened):

6. Separation of Concerns
7. Explicit State
8. Jurisdiction Primacy
9. Evidence Sufficiency
10. Permit Requirement

### Change Process

1. Propose refinement with rationale
2. Demonstrate no weakening of guarantees
3. Update all dependent specifications
4. Update all tests
5. Version bump (major if axiom change)
