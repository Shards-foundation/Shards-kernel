# Shards-Kernel Framework Guide

**Version:** 0.1.0  
**Classification:** Developer Guide  
**Last Updated:** January 2025

---

## 1. Introduction

Shards-Kernel is a **deterministic control plane framework** for AI systems. It provides governance, audit, and policy enforcement for AI agent actions.

### 1.1 What is Shards-Kernel?

Shards-Kernel is a runtime governance layer that:

- **Interposes** between AI agent intent and action execution
- **Arbitrates** every action against explicit policy
- **Records** every decision in an immutable audit trail
- **Fails closed** when faced with ambiguity

### 1.2 Key Features

| Feature | Description |
|---------|-------------|
| **Fail-Closed** | Default deny, explicit allow required |
| **Deterministic** | Same inputs always produce same outputs |
| **Auditable** | Hash-chained immutable audit ledger |
| **Extensible** | Custom policies, tools, and integrations |
| **Zero Dependencies** | Python stdlib only |

### 1.3 When to Use Shards-Kernel

Use Shards-Kernel when you need:

- Governance for AI agent actions
- Audit trail for compliance
- Policy enforcement at runtime
- Deterministic decision-making
- Emergency halt capability

---

## 2. Core Concepts

### 2.1 The Kernel

The **kernel** is the central decision engine. It:

1. Receives requests from agents
2. Validates request structure
3. Evaluates against jurisdiction policy
4. Executes permitted actions
5. Records decisions in audit ledger
6. Returns receipts to agents

```
Agent → Request → [Kernel] → Receipt → Agent
                     ↓
                 Audit Ledger
```

### 2.2 Requests and Receipts

**Request:** What the agent wants to do

```python
Request(
    request_id="req-001",
    actor="agent-001",
    intent="Read configuration file",
    tool_call=ToolCall(name="read_file", params={"path": "/config.yaml"}),
)
```

**Receipt:** The kernel's response

```python
Receipt(
    request_id="req-001",
    status="ACCEPTED",
    decision=Decision.ALLOW,
    result={"content": "..."},
)
```

### 2.3 Decisions

| Decision | Meaning |
|----------|---------|
| `ALLOW` | Request permitted and executed |
| `DENY` | Request denied, not executed |
| `HALT` | Kernel halted, no further processing |

### 2.4 Kernel States

```
BOOTING → IDLE ⟷ VALIDATING → ARBITRATING → EXECUTING → AUDITING → IDLE
                                                              ↓
Any state ──────────────────────────────────────────────▶ HALTED
```

| State | Description |
|-------|-------------|
| `BOOTING` | Kernel initializing |
| `IDLE` | Ready for requests |
| `VALIDATING` | Checking request structure |
| `ARBITRATING` | Evaluating policy |
| `EXECUTING` | Running tool |
| `AUDITING` | Recording decision |
| `HALTED` | Terminal state |

### 2.5 Jurisdiction Policy

Policy defines what the kernel permits:

```python
JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],
    allowed_tools=["read_file", "write_file"],
    require_tool_call=True,
    max_intent_length=1000,
)
```

### 2.6 Audit Ledger

Every decision is recorded in a hash-chained ledger:

```
Entry 0 ← Entry 1 ← Entry 2 ← Entry 3
  ↓          ↓          ↓          ↓
hash_0    hash_1    hash_2    hash_3
```

Each entry contains:
- Request details
- Decision made
- State transition
- Timestamp
- Hash of previous entry

---

## 3. Architecture

### 3.1 Four Planes Model

```
┌─────────────────────────────────────────────────────────────┐
│                    OPERATIONS PLANE                         │
│              (Cockpit, CI/CD, Monitoring)                   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    GOVERNANCE PLANE                         │
│                       (Kernel)                              │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    EXECUTION PLANE                          │
│                      (Workers)                              │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    PERCEPTION PLANE                         │
│                      (Sensors)                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **Kernel** | Decide (governance) |
| **Workers** | Execute (actions) |
| **Sensors** | Observe (environment) |
| **Cockpit** | Manage (operations) |

### 3.3 Module Structure

```
shards_kernel/
├── api.py              # Public API surface
├── common/             # Shared utilities
│   ├── types.py        # Core types
│   ├── errors.py       # Exceptions
│   └── hashing.py      # Hash utilities
├── audit/              # Audit subsystem
│   ├── ledger.py       # Append-only ledger
│   └── replay.py       # Verification
├── jurisdiction/       # Policy subsystem
│   ├── policy.py       # Policy definition
│   └── rules.py        # Rule evaluation
├── state/              # State machine
│   ├── machine.py      # State machine
│   └── transitions.py  # Transitions
├── execution/          # Tool execution
│   ├── tools.py        # Tool registry
│   └── dispatcher.py   # Dispatcher
└── variants/           # Kernel variants
    ├── strict_kernel/
    ├── permissive_kernel/
    ├── evidence_first_kernel/
    └── dual_channel_kernel/
```

---

## 4. Kernel Variants

### 4.1 StrictKernel

**Maximum enforcement.** Use in production.

```python
from shards_kernel import StrictKernel

kernel = StrictKernel(kernel_id="prod-001")
```

**Characteristics:**
- Strict validation
- Requires tool_call
- Low ambiguity tolerance
- Full audit

### 4.2 PermissiveKernel

**Relaxed thresholds.** Use in development.

```python
from shards_kernel import PermissiveKernel

kernel = PermissiveKernel(kernel_id="dev-001")
```

**Characteristics:**
- Lenient validation
- Intent-only allowed
- Higher ambiguity tolerance
- Full audit

### 4.3 EvidenceFirstKernel

**Evidence required.** Use for audit-heavy workloads.

```python
from shards_kernel import EvidenceFirstKernel

kernel = EvidenceFirstKernel(kernel_id="audit-001")
```

**Characteristics:**
- Requires evidence field
- Strict validation
- Evidence binding
- Enhanced audit

### 4.4 DualChannelKernel

**Constraints required.** Use for structured workflows.

```python
from shards_kernel import DualChannelKernel

kernel = DualChannelKernel(kernel_id="structured-001")
```

**Characteristics:**
- Requires constraints dict
- Scope, non_goals, success_criteria
- Structured proposals
- Full audit

### 4.5 Variant Selection Guide

| Use Case | Recommended Variant |
|----------|---------------------|
| Production | StrictKernel |
| Development | PermissiveKernel |
| Compliance-heavy | EvidenceFirstKernel |
| Complex workflows | DualChannelKernel |

---

## 5. Core Invariants

Shards-Kernel guarantees these invariants:

| ID | Invariant | Guarantee |
|----|-----------|-----------|
| 1 | **Single State** | Exactly one state at any time |
| 2 | **Explicit Transitions** | No implicit state changes |
| 3 | **Jurisdiction Check** | Policy evaluated before execution |
| 4 | **Audit Before Transition** | Entry created before state change |
| 5 | **Hash Chain** | Each entry links to previous |
| 6 | **Fail-Closed** | Ambiguity results in DENY |
| 7 | **Determinism** | Same inputs produce same outputs |
| 8 | **Halt Authority** | Halt always available |
| 9 | **Evidence Export** | Decisions are exportable |
| 10 | **No Implicit Allow** | Explicit ALLOW required |

---

## 6. Extension Points

### 6.1 Custom Tools

Register custom tools for execution:

```python
from shards_kernel.execution import ToolRegistry

registry = ToolRegistry()

@registry.register("my_tool")
def my_tool(params):
    return {"result": "success"}
```

### 6.2 Custom Rules

Add custom policy rules:

```python
from shards_kernel.jurisdiction import RuleResult

def my_rule(request):
    if some_condition(request):
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Condition not met")

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["tool"],
    custom_rules=[my_rule],
)
```

### 6.3 Custom Validators

Add custom request validators:

```python
def my_validator(request):
    if not valid(request):
        raise ValidationError("Invalid request")
    return True

kernel.add_validator(my_validator)
```

### 6.4 Event Hooks

Subscribe to kernel events:

```python
@kernel.on("request_received")
def on_request(request):
    log.info(f"Received: {request.request_id}")

@kernel.on("decision_made")
def on_decision(request, decision):
    log.info(f"Decision: {decision}")
```

---

## 7. Best Practices

### 7.1 Policy Design

| Practice | Rationale |
|----------|-----------|
| Enumerate actors explicitly | No wildcards |
| Enumerate tools explicitly | Least privilege |
| Start restrictive | Add permissions as needed |
| Review regularly | Remove unused permissions |

### 7.2 Error Handling

```python
from shards_kernel import KernelError, JurisdictionError, StateError

try:
    receipt = kernel.submit(request)
except JurisdictionError as e:
    log.warning(f"Policy violation: {e}")
except StateError as e:
    log.error(f"State error: {e}")
except KernelError as e:
    log.error(f"Kernel error: {e}")
```

### 7.3 Evidence Management

| Practice | Rationale |
|----------|-----------|
| Export regularly | Prevent data loss |
| Verify after export | Ensure integrity |
| Store immutably | Compliance requirement |
| Retain per policy | Legal requirement |

### 7.4 Monitoring

| Metric | Alert Threshold |
|--------|-----------------|
| Kernel state | != IDLE for > 5 min |
| Decision latency | p99 > 100ms |
| Deny rate | > 50% in 5 min |
| Error rate | > 1% in 5 min |

---

## 8. Integration Patterns

### 8.1 Synchronous Integration

```python
# Agent submits and waits
receipt = kernel.submit(request)
if receipt.decision == Decision.ALLOW:
    process_result(receipt.result)
```

### 8.2 Async Integration

```python
# Agent submits and continues
async def process_request(request):
    receipt = await kernel.submit_async(request)
    return receipt
```

### 8.3 Batch Integration

```python
# Process multiple requests
requests = [create_request(i) for i in range(100)]
receipts = kernel.submit_batch(requests)
```

### 8.4 Event-Driven Integration

```python
# Subscribe to decisions
@kernel.on("decision_made")
async def handle_decision(request, decision, receipt):
    await notify_agent(request.actor, receipt)
```

---

## 9. Security Considerations

### 9.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious agent | Jurisdiction policy |
| Audit tampering | Hash chain |
| Unauthorized access | Actor allow list |
| Scope creep | Tool allow list |

### 9.2 Hardening

| Measure | Implementation |
|---------|----------------|
| Input validation | Validate all fields |
| Rate limiting | Per-actor limits |
| Size limits | Max intent length |
| TLS | Encrypt in transit |

### 9.3 Secrets

| Secret | Handling |
|--------|----------|
| Signing keys | Vault, rotate 90 days |
| API tokens | Environment variables |
| Credentials | Never in code |

---

## 10. Performance

### 10.1 Benchmarks

| Metric | Value |
|--------|-------|
| Decision latency | <1ms (p99) |
| Throughput | >10,000 req/s |
| Memory overhead | <10MB |

### 10.2 Optimization

| Technique | Benefit |
|-----------|---------|
| Connection pooling | Reduce overhead |
| Batch processing | Amortize costs |
| Async execution | Improve throughput |
| Caching | Reduce computation |

---

## 11. Troubleshooting

### 11.1 Common Issues

| Issue | Solution |
|-------|----------|
| Request denied | Check actor/tool in policy |
| Kernel stuck | Check state, consider halt |
| Chain invalid | Export and verify evidence |
| High latency | Check tool execution time |

### 11.2 Debugging

```python
# Enable debug logging
import logging
logging.getLogger("kernels").setLevel(logging.DEBUG)

# Inspect kernel state
print(kernel.state)
print(kernel.policy)

# Export evidence for analysis
evidence = kernel.export_evidence()
```

---

## 12. Next Steps

1. **Quick Start:** See [QUICKSTART.md](QUICKSTART.md)
2. **Cookbook:** See [COOKBOOK.md](COOKBOOK.md)
3. **API Reference:** See [API.md](../sdk/API.md)
4. **Examples:** See `/examples/` directory
