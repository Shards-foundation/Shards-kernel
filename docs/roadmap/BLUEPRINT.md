# Shards-Kernel Project Blueprint

**Version:** 0.1.0  
**Classification:** Technical Architecture  
**Last Updated:** January 2025

---

## 1. System Overview

Shards-Kernel is a deterministic control plane that interposes between AI agents and tool execution. It provides governance through explicit jurisdiction, fail-closed arbitration, and immutable audit.

### 1.1 Core Thesis

> Every AI agent action must pass through a deterministic decision boundary that produces verifiable evidence.

### 1.2 Design Principles

| Principle | Implementation |
|-----------|----------------|
| Determinism | Pure functions, no side effects in decision path |
| Fail-closed | Default deny, explicit allow required |
| Auditability | Every transition recorded before completion |
| Separation | Kernel decides, workers execute, sensors observe |
| Minimalism | One job per component |

---

## 2. Architecture Blueprint

### 2.1 Four Planes Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OPERATIONS PLANE                                │
│                    (Cockpit, CI/CD, Monitoring)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │   Approvals  │  │   Dashboard  │  │    Replay    │                  │
│  │      UI      │  │              │  │    Viewer    │                  │
│  └──────────────┘  └──────────────┘  └──────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
                              │ Approval/Status
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        GOVERNANCE PLANE                                 │
│                           (Kernel)                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │   Proposal   │  │ Jurisdiction │  │    State     │  │   Audit    │  │
│  │  Validator   │  │    Engine    │  │   Machine    │  │   Ledger   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                              │ Permit Token
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXECUTION PLANE                                  │
│                          (Workers)                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │     MCP      │  │   Webhook    │  │     API      │  │  Browser   │  │
│  │   Server     │  │   Actuator   │  │   Executor   │  │   Driver   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                              │ Action/Observation
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        PERCEPTION PLANE                                 │
│                          (Sensors)                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │   Browser    │  │   Webhook    │  │     API      │  │    File    │  │
│  │  Extension   │  │  Collector   │  │   Observer   │  │   Watcher  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

| Component | Plane | Responsibility | Trust Level |
|-----------|-------|----------------|-------------|
| Kernel | Governance | Decide | High |
| State Machine | Governance | Track state | High |
| Jurisdiction Engine | Governance | Enforce policy | High |
| Audit Ledger | Governance | Record decisions | High |
| MCP Server | Execution | Execute tools | Medium |
| Webhook Actuator | Execution | Trigger webhooks | Medium |
| Browser Extension | Perception | Capture DOM | Low |
| Webhook Collector | Perception | Receive events | Low |
| Cockpit | Operations | Display/approve | Medium |

---

## 3. Data Flow Blueprint

### 3.1 Request Flow

```
Agent                Kernel              Worker              External
  │                    │                    │                    │
  │  1. Proposal       │                    │                    │
  │───────────────────▶│                    │                    │
  │                    │                    │                    │
  │                    │ 2. Validate        │                    │
  │                    │◀──────────────────▶│                    │
  │                    │                    │                    │
  │                    │ 3. Arbitrate       │                    │
  │                    │ (check policy)     │                    │
  │                    │                    │                    │
  │                    │ 4. Audit           │                    │
  │                    │ (record decision)  │                    │
  │                    │                    │                    │
  │                    │ 5. Permit Token    │                    │
  │                    │───────────────────▶│                    │
  │                    │                    │                    │
  │                    │                    │ 6. Execute         │
  │                    │                    │───────────────────▶│
  │                    │                    │                    │
  │                    │                    │ 7. Result          │
  │                    │                    │◀───────────────────│
  │                    │                    │                    │
  │                    │ 8. Execution Audit │                    │
  │                    │◀───────────────────│                    │
  │                    │                    │                    │
  │  9. Receipt        │                    │                    │
  │◀───────────────────│                    │                    │
  │                    │                    │                    │
```

### 3.2 Evidence Flow

```
External             Sensor              Kernel              Agent
  │                    │                    │                    │
  │  1. State Change   │                    │                    │
  │───────────────────▶│                    │                    │
  │                    │                    │                    │
  │                    │ 2. Observe         │                    │
  │                    │ (capture state)    │                    │
  │                    │                    │                    │
  │                    │ 3. Evidence Packet │                    │
  │                    │───────────────────▶│                    │
  │                    │                    │                    │
  │                    │                    │ 4. Store           │
  │                    │                    │ (validate, index)  │
  │                    │                    │                    │
  │                    │                    │ 5. Available       │
  │                    │                    │───────────────────▶│
  │                    │                    │                    │
```

---

## 4. State Machine Blueprint

### 4.1 States

| State | Description | Entry Condition |
|-------|-------------|-----------------|
| BOOTING | Initializing | Kernel created |
| IDLE | Ready for requests | Boot complete / audit complete |
| VALIDATING | Checking request | Request received |
| ARBITRATING | Evaluating policy | Validation passed |
| EXECUTING | Running tool | Decision = ALLOW |
| AUDITING | Recording decision | Decision made |
| HALTED | Terminal | Halt command / unhandled error |

### 4.2 Transitions

```
                    ┌─────────────────────────────────────────┐
                    │                                         │
                    ▼                                         │
              ┌─────────┐                                     │
              │ BOOTING │                                     │
              └────┬────┘                                     │
                   │ boot_complete                            │
                   ▼                                          │
              ┌─────────┐◀────────────────────────────────────┤
              │  IDLE   │                                     │
              └────┬────┘                                     │
                   │ request_received                         │
                   ▼                                          │
            ┌───────────┐                                     │
            │VALIDATING │                                     │
            └─────┬─────┘                                     │
                  │                                           │
        ┌─────────┴─────────┐                                 │
        │                   │                                 │
        ▼                   ▼                                 │
  validation_ok      validation_fail                          │
        │                   │                                 │
        ▼                   │                                 │
  ┌───────────┐             │                                 │
  │ARBITRATING│             │                                 │
  └─────┬─────┘             │                                 │
        │                   │                                 │
  ┌─────┴─────┐             │                                 │
  │           │             │                                 │
  ▼           ▼             │                                 │
ALLOW       DENY            │                                 │
  │           │             │                                 │
  ▼           │             │                                 │
┌─────────┐   │             │                                 │
│EXECUTING│   │             │                                 │
└────┬────┘   │             │                                 │
     │        │             │                                 │
     ▼        ▼             ▼                                 │
  ┌──────────────────────────┐                                │
  │        AUDITING          │                                │
  └────────────┬─────────────┘                                │
               │                                              │
               └──────────────────────────────────────────────┘
               
Any state ──────────────────────────────────────────▶ HALTED
           (halt_command or unhandled_exception)
```

---

## 5. Security Blueprint

### 5.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED BOUNDARY                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                     KERNEL                           │   │
│  │  • State machine                                     │   │
│  │  • Jurisdiction engine                               │   │
│  │  • Audit ledger                                      │   │
│  │  • Permit minting                                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                    ══════════╪══════════  Trust boundary
                              │
┌─────────────────────────────────────────────────────────────┐
│                   SEMI-TRUSTED BOUNDARY                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    WORKERS                           │   │
│  │  • Permit verification                               │   │
│  │  • Tool execution                                    │   │
│  │  • Result reporting                                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                    ══════════╪══════════  Trust boundary
                              │
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED BOUNDARY                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    SENSORS                           │   │
│  │  • Browser extension                                 │   │
│  │  • Webhook collectors                                │   │
│  │  • External observers                                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Attack Surface

| Surface | Risk | Mitigation |
|---------|------|------------|
| Proposal input | Injection | Schema validation |
| Evidence packets | Spoofing | Signature verification |
| Permit tokens | Forgery | HMAC signing |
| Audit ledger | Tampering | Hash chain |
| Worker execution | Escalation | Permit scoping |

---

## 6. Deployment Blueprint

### 6.1 Single-Node Deployment

```
┌─────────────────────────────────────────┐
│              Application                │
│  ┌─────────────────────────────────┐   │
│  │           Kernel                 │   │
│  │  ┌─────────┐  ┌─────────────┐   │   │
│  │  │  State  │  │   Audit     │   │   │
│  │  │ Machine │  │   Ledger    │   │   │
│  │  └─────────┘  │ (in-memory) │   │   │
│  │               └─────────────┘   │   │
│  └─────────────────────────────────┘   │
│  ┌─────────────────────────────────┐   │
│  │        Tool Registry             │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 6.2 Multi-Node Deployment (Future)

```
┌─────────────────┐     ┌─────────────────┐
│  Kernel Node 1  │     │  Kernel Node 2  │
│  (Active)       │     │  (Standby)      │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
              ┌──────┴──────┐
              │  PostgreSQL │
              │  (Ledger)   │
              └──────┬──────┘
                     │
              ┌──────┴──────┐
              │    Redis    │
              │  (State)    │
              └─────────────┘
```

---

## 7. Testing Blueprint

### 7.1 Test Pyramid

```
                    ┌───────────┐
                    │   E2E     │  5%
                    │  Tests    │
                    └─────┬─────┘
                    ┌─────┴─────┐
                    │Integration│  15%
                    │  Tests    │
                    └─────┬─────┘
              ┌───────────┴───────────┐
              │      Unit Tests       │  80%
              │  (State, Policy,      │
              │   Audit, Hashing)     │
              └───────────────────────┘
```

### 7.2 Test Categories

| Category | Focus | Tools |
|----------|-------|-------|
| Unit | Individual functions | unittest |
| Property | Invariant preservation | hypothesis |
| Fuzz | Input validation | atheris |
| Integration | Component interaction | pytest |
| E2E | Full request flow | pytest |
| Security | Vulnerability detection | bandit, safety |

---

## 8. Monitoring Blueprint

### 8.1 Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kernel_requests_total` | Counter | Total requests received |
| `kernel_decisions_total` | Counter | Decisions by type (ALLOW/DENY/HALT) |
| `kernel_decision_latency_ms` | Histogram | Decision time |
| `kernel_audit_entries_total` | Counter | Audit entries created |
| `kernel_state` | Gauge | Current state |

### 8.2 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| KernelHalted | state = HALTED | Critical |
| HighDenyRate | deny_rate > 50% | Warning |
| AuditLagHigh | audit_lag > 100ms | Warning |
| HashChainBroken | chain_valid = false | Critical |

---

## 9. Evolution Blueprint

### 9.1 Extension Points

| Point | Mechanism | Use Case |
|-------|-----------|----------|
| Kernel variants | Subclass BaseKernel | Custom postures |
| Tools | ToolRegistry.register() | New capabilities |
| Policies | JurisdictionPolicy | Custom rules |
| Sensors | EvidencePacket schema | New evidence types |

### 9.2 Deprecation Policy

| Phase | Timeline | Action |
|-------|----------|--------|
| Deprecation | v0.x.0 | Mark deprecated, warn |
| Migration | v0.x.0 + 2 minor | Provide migration path |
| Removal | v0.x.0 + 4 minor | Remove deprecated code |
