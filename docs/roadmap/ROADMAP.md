# Shards-Kernel Roadmap

**Version:** 0.1.0  
**Last Updated:** Capability progression (non-dated)

---

## Vision

Shards-Kernel becomes the standard control plane for governed AI agent execution, making deterministic arbitration and immutable audit the default for production AI systems.

---

## Capability Progression

```
Phase 1         Phase 2         Phase 3         Phase 4
    │                │                │                │
    ▼                ▼                ▼                ▼
┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐
│ v0.1.x │      │ v0.2.x │      │ v0.3.x │      │ v1.0.0 │
│ Found- │      │ Harden │      │ Scale  │      │ Stable │
│ ation  │      │        │      │        │      │        │
└────────┘      └────────┘      └────────┘      └────────┘
```

---

## Phase 1: Foundation (v0.1.x) — CURRENT

**Status:** ✅ Complete  
**Progression Slot:** Initial foundation capabilities

### Deliverables

| Item | Status | Notes |
|------|--------|-------|
| Core state machine | ✅ Done | 7 states, defined transitions |
| Jurisdiction policy | ✅ Done | Actor/tool allow lists |
| Audit ledger | ✅ Done | Append-only, hash-chained |
| Fail-closed semantics | ✅ Done | Ambiguity → DENY |
| Four kernel variants | ✅ Done | Strict, Permissive, Evidence, Dual |
| CLI tools | ✅ Done | info, validate, replay |
| Test suite | ✅ Done | 64 tests passing |
| Documentation | ✅ Done | Specs, architecture, threat model |

### Metrics

| Metric | Target | Actual |
|--------|--------|--------|
| Test pass rate | 100% | 100% |
| Core invariants | 10 | 10 |
| Spec documents | 7+ | 12 |
| Examples | 5 | 5 |

---

## Phase 2: Hardening (v0.2.x)

**Status:** 🔄 In Progress  
**Progression Slot:** Security and reliability hardening

### Deliverables

| Item | Status | Priority |
|------|--------|----------|
| Security audit | 🔄 In Progress | P0 |
| Permit token implementation | 🔲 Planned | P0 |
| Proposal schema implementation | 🔲 Planned | P0 |
| Evidence packet handling | 🔲 Planned | P1 |
| CI/CD pipeline | 🔲 Planned | P1 |
| Property-based testing | 🔲 Planned | P1 |
| Fuzz testing | 🔲 Planned | P2 |
| Performance benchmarks | 🔲 Planned | P2 |

### Milestones

| Milestone | Sequence | Criteria |
|-----------|----------|----------|
| M2.1 Security audit complete | First | No critical findings |
| M2.2 Permit tokens working | Second | End-to-end flow |
| M2.3 CI/CD operational | Third | Auto-test on PR |
| M2.4 v0.2.0 release | Fourth | All P0 items done |

---

## Phase 3: Scale (v0.3.x)

**Status:** 🔲 Planned  
**Progression Slot:** Scalability and distributed architecture

### Deliverables

| Item | Priority | Description |
|------|----------|-------------|
| Async execution | P0 | Non-blocking tool dispatch |
| Horizontal scaling | P1 | Multi-instance coordination |
| Persistent ledger | P1 | Database-backed audit |
| Metrics export | P2 | Prometheus/OpenTelemetry |
| Rate limiting | P2 | Request throttling |

### Architecture Changes

```
Current (v0.1.x):
┌─────────────────┐
│  Single Kernel  │
│  In-Memory      │
└─────────────────┘

Future (v0.3.x):
┌─────────────────┐     ┌─────────────────┐
│  Kernel Node 1  │────▶│  Shared Ledger  │
└─────────────────┘     │  (PostgreSQL)   │
┌─────────────────┐     │                 │
│  Kernel Node 2  │────▶│                 │
└─────────────────┘     └─────────────────┘
```

---

## Phase 4: Ecosystem (v0.4.x - v1.0.0)

**Status:** 🔲 Planned  
**Progression Slot:** Ecosystem integrations and platform maturity

### Deliverables

| Item | Priority | Description |
|------|----------|-------------|
| MCP integration | P0 | Permit-gated MCP tools |
| Browser extension SDK | P1 | Evidence sensor framework |
| Webhook adapters | P1 | Inbound/outbound webhooks |
| Python SDK | P1 | High-level client library |
| TypeScript SDK | P2 | Node.js/browser support |
| Cockpit UI | P2 | Approval/status dashboard |

### Integration Points

| Integration | Type | Status |
|-------------|------|--------|
| MCP (Model Context Protocol) | Tool bus | 🔲 Planned |
| OpenTelemetry | Observability | 🔲 Planned |
| PostgreSQL | Persistence | 🔲 Planned |
| Redis | Caching | 🔲 Planned |
| Kubernetes | Deployment | 🔲 Planned |

---

## v1.0.0 Release Criteria

**Target:** After Phase 4 criteria are satisfied

### Must Have

| Criterion | Description |
|-----------|-------------|
| Invariants frozen | No changes to 10 core invariants |
| API frozen | Public API surface stable |
| Security audit passed | No critical/high findings |
| Performance validated | <10ms decision latency |
| Documentation complete | 100% public API coverage |
| Production deployments | 3+ reference deployments |

### Nice to Have

| Criterion | Description |
|-----------|-------------|
| Community contributions | 5+ external contributors |
| Ecosystem tools | 2+ third-party integrations |
| Enterprise features | SSO, audit export, compliance |

---

## Long-Term Vision (v2.x+)

### Long Horizon

| Area | Vision |
|------|--------|
| Multi-agent coordination | Kernel federation for agent swarms |
| Formal verification | Prove invariant preservation |
| Hardware security | HSM-backed signing |
| Regulatory compliance | SOC2, HIPAA, GDPR modules |
| Industry standards | Contribute to AI governance standards |

---

## Contributing to Roadmap

### How to Propose Features

1. Open GitHub issue with `[ROADMAP]` prefix
2. Include: problem, solution, success criteria
3. Tag with appropriate phase (v0.2, v0.3, etc.)
4. Discuss in issue before PR

### Prioritization Criteria

| Factor | Weight |
|--------|--------|
| Invariant preservation | Must have |
| Security impact | High |
| User demand | Medium |
| Implementation complexity | Medium |
| Maintenance burden | Low |

---

## Methodology

Timeline language is intentionally non-dated and ordered by capability progression to avoid unsupported calendar claims; dates are only retained when directly verifiable from commit metadata.

## Revision Notes

| Entry | Change |
|------|--------|
| 1 | Initial roadmap created |
| 2 | Phase 1 marked complete |
| 3 | Phase 2 started |
