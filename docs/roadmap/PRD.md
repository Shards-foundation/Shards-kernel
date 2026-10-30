# Product Requirements Document (PRD)

**Product:** Shards-Kernel — Deterministic Control Planes for AI Systems  
**Version:** 0.1.0  
**Status:** Development  
**Last Updated:** January 2025

---

## 1. Executive Summary

Shards-Kernel is a deterministic control plane that governs AI agent execution through explicit jurisdiction, fail-closed arbitration, and append-only hash-chained audit. It solves the operational problem of ungoverned agent systems that fail in predictable, dangerous ways.

### 1.1 Problem Statement

Ungoverned AI agent systems exhibit five critical failure modes:

| Failure Mode | Business Impact |
|--------------|-----------------|
| Ambiguity escapes into execution | Unauditable actions, liability exposure |
| Implicit state drift | Post-hoc analysis impossible |
| Tool reach exceeds operator intent | Unauthorized operations |
| Advisory logs | Incomplete audit trails |
| Accountability diffusion | No provenance for decisions |

### 1.2 Solution

Shards-Kernel provides a deterministic state machine that sits between operators (humans with authority) and agents (AI systems that execute). Every action requires explicit approval, every decision is audited, and ambiguity results in denial.

---

## 2. Goals and Non-Goals

### 2.1 Goals

| ID | Goal | Success Metric |
|----|------|----------------|
| G1 | Deterministic arbitration | 100% reproducible decisions given same inputs |
| G2 | Complete audit trail | Zero missing transitions in ledger |
| G3 | Fail-closed semantics | Zero implicit allows |
| G4 | Jurisdiction enforcement | Zero out-of-scope executions |
| G5 | Evidence exportability | Any decision verifiable externally |

### 2.2 Non-Goals

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | LLM integration | Kernel governs, doesn't call models |
| NG2 | Prompt engineering | Not a prompt framework |
| NG3 | Agent behavior definition | Constrains, doesn't define |
| NG4 | Value alignment | Operational boundaries, not ethics |
| NG5 | Visualization/dashboards | Outputs evidence, display is external |

---

## 3. User Personas

### 3.1 Operator (Primary)

**Role:** Human with authority over AI system deployment

**Needs:**
- Define jurisdiction policies
- Review audit evidence
- Issue halt commands
- Approve high-risk actions

**Pain Points:**
- Cannot prove why AI took an action
- No single source of truth for decisions
- Agents exceed intended scope

### 3.2 Developer (Secondary)

**Role:** Engineer integrating Shards-Kernel into AI systems

**Needs:**
- Clear API surface
- Deterministic behavior for testing
- Extensible tool registry
- Comprehensive documentation

**Pain Points:**
- Non-deterministic AI behavior
- Difficult to test agent systems
- Unclear failure modes

### 3.3 Auditor (Tertiary)

**Role:** Compliance/security reviewer

**Needs:**
- Complete audit trails
- Verifiable evidence bundles
- Replay capability
- Hash chain integrity

**Pain Points:**
- Incomplete logs
- Non-reproducible decisions
- Missing provenance

---

## 4. Requirements

### 4.1 Functional Requirements

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR1 | State machine with defined transitions | P0 | ✅ Done |
| FR2 | Jurisdiction policy enforcement | P0 | ✅ Done |
| FR3 | Append-only hash-chained audit | P0 | ✅ Done |
| FR4 | Fail-closed on ambiguity | P0 | ✅ Done |
| FR5 | Tool registry with dispatch | P0 | ✅ Done |
| FR6 | Evidence bundle export | P0 | ✅ Done |
| FR7 | External replay verification | P0 | ✅ Done |
| FR8 | Multiple kernel variants | P1 | ✅ Done |
| FR9 | CLI for validation/replay | P1 | ✅ Done |
| FR10 | Permit token minting | P1 | 🔲 Spec |
| FR11 | Structured proposal schema | P1 | 🔲 Spec |
| FR12 | Evidence packet handling | P1 | 🔲 Spec |

### 4.2 Non-Functional Requirements

| ID | Requirement | Target | Status |
|----|-------------|--------|--------|
| NFR1 | Determinism | 100% reproducible | ✅ Done |
| NFR2 | Latency | <10ms per decision | ✅ Done |
| NFR3 | Test coverage | >80% | 🔲 Pending |
| NFR4 | Documentation | Complete specs | ✅ Done |
| NFR5 | Security audit | No critical findings | 🔲 Pending |

---

## 5. Feature Specifications

### 5.1 Core Invariants

The kernel MUST satisfy these invariants at all times:

| Invariant | Description | Enforcement |
|-----------|-------------|-------------|
| INV-STATE | Single state at any time | State machine |
| INV-TRANSITION | Explicit transitions only | Transition functions |
| INV-JURISDICTION | Policy check before execution | Policy engine |
| INV-AUDIT | Entry before transition completes | Ledger append |
| INV-HASH-CHAIN | Entries chain to previous | Hash computation |
| INV-FAIL-CLOSED | Ambiguity → DENY/HALT | Default deny |
| INV-DETERMINISM | Same inputs → same outputs | Pure functions |
| INV-HALT | Immediate halt available | Halt command |
| INV-EVIDENCE | Decisions exportable | Evidence bundle |
| INV-NO-IMPLICIT-ALLOW | Explicit ALLOW required | Decision check |

### 5.2 Kernel Variants

| Variant | Posture | Use Case |
|---------|---------|----------|
| StrictKernel | Maximum enforcement | Production, high-risk |
| PermissiveKernel | Relaxed thresholds | Development, low-risk |
| EvidenceFirstKernel | Evidence required | Audit-heavy environments |
| DualChannelKernel | Constraints required | Structured workflows |

---

## 6. Success Metrics

### 6.1 Adoption Metrics

| Metric | Target (6 months) |
|--------|-------------------|
| GitHub stars | 500+ |
| PyPI downloads | 1,000+/month |
| Production deployments | 10+ |
| Contributors | 5+ |

### 6.2 Quality Metrics

| Metric | Target |
|--------|--------|
| Test pass rate | 100% |
| Bug escape rate | <1/month |
| Documentation coverage | 100% of public API |
| Security vulnerabilities | 0 critical/high |

---

## 7. Timeline

### Phase 1: Foundation (Complete)
- Core state machine
- Jurisdiction policy
- Audit ledger
- Basic variants
- CLI tools

### Phase 2: Hardening (Current)
- Security audit
- Permit token implementation
- Proposal schema implementation
- Evidence packet handling
- CI/CD pipeline

### Phase 3: Production (Q2 2025)
- Performance optimization
- Horizontal scaling
- Cloud deployment guides
- Enterprise features

### Phase 4: Ecosystem (Q3 2025)
- MCP integration
- Browser extension SDK
- Webhook adapters
- Community tools

---

## 8. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Adoption resistance | Medium | High | Clear documentation, examples |
| Security vulnerability | Low | Critical | Security audit, hardening |
| Performance bottleneck | Low | Medium | Profiling, optimization |
| Scope creep | Medium | Medium | Strict non-goals enforcement |
| Maintainer burnout | Medium | High | Community building |

---

## 9. Appendices

### 9.1 Glossary

See `spec/GLOSSARY.md` for authoritative term definitions.

### 9.2 References

- `spec/SPEC.md` — Normative specification
- `docs/ARCHITECTURE.md` — System architecture
- `docs/THREAT_MODEL.md` — Security analysis
