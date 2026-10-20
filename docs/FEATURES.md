# KERNELS Key Features

**Version:** 0.1.0  
**Classification:** Overview  
**Last Updated:** January 2025

---

## 1. Overview

KERNELS is a deterministic control plane for AI systems. This document describes its key features.

---

## 2. Core Features

### 2.1 Deterministic State Machine

KERNELS operates as a **finite state machine** with eight states and deterministic transitions. `HALTED` is the only terminal state. `COMPLETED` means one request has been audited; the kernel then returns to `IDLE`.

```
BOOTING → IDLE → VALIDATING → ARBITRATING → AUDITING (intent)
        → EXECUTING → AUDITING (outcome) → COMPLETED → IDLE
Any unhandled exception → HALTED
```

**Benefits:**
- Predictable behavior
- Auditable state transitions
- No hidden states
- Reproducible execution

**Example:**
```python
from kernels import StrictKernel

kernel = StrictKernel(kernel_id="demo")
print(kernel.state)  # KernelState.IDLE

receipt = kernel.submit(request)
print(kernel.state)  # KernelState.IDLE (returned after processing)
```

---

### 2.2 Fail-Closed Semantics

KERNELS **defaults to DENY** when policy is ambiguous or errors occur. An ambiguous request is denied even if `fail_closed` is set to false. A tool call is denied unless `submit` receives a permit whose parameters are the parameters that run.

**Principle:** When in doubt, deny.

**Benefits:**
- Secure by default
- No accidental permissions
- Explicit allow required

**Example:**
```python
from kernels import StrictKernel
from kernels.common.types import KernelConfig, KernelRequest, ToolCall, VirtualClock
from kernels.permits import PermitBuilder

kernel = StrictKernel()
kernel.boot(KernelConfig(kernel_id="secure", variant="strict", clock=VirtualClock(0)))
keyring = {"k": b"test-secret-key-32-bytes-long123"}
kernel.set_keyring(keyring)
params = {"text": "hello"}
permit = (
    PermitBuilder()
    .issuer("operator")
    .subject("agent")
    .jurisdiction("default")
    .action("echo")
    .params(params)
    .max_executions(1)
    .valid_from_ms(0)
    .valid_until_ms(10_000)
    .proposal_hash("proposal-echo")
    .build(keyring, "k")
)
request = KernelRequest(
    request_id="req-1",
    ts_ms=0,
    actor="agent",
    intent="Echo hello",
    tool_call=ToolCall(name="echo", params=dict(params)),
    params=dict(params),
)
receipt = kernel.submit(request, permit_token=permit)
```

---

### 2.3 Append-Only Audit Ledger

Every request is recorded in an **immutable, hash-chained ledger**.

**Properties:**
- Append-only (no modifications)
- Hash-chained (tamper-evident)
- Externally verifiable
- Complete history
- Process memory only. The reference ledger does not write a file and does not fsync. Export the bundle to keep it.

**Example:**
```python
# Export evidence
evidence = kernel.export_evidence()
print(f"Entries: {evidence['entry_count']}")
print(f"Root hash: {evidence['root_hash']}")

# Verify integrity
from kernels.audit import replay_and_verify
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)
print(f"Valid: {is_valid}")
```

---

### 2.4 Jurisdiction Policy

Fine-grained control over **who can do what**.

**Controls:**
- Actor allow list
- Tool allow list
- Intent length limits
- Custom rules

**Example:**
```python
from kernels import JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],
    allowed_tools=["read_file", "search"],
    require_tool_call=True,
    max_intent_length=1000,
)
```

---

### 2.5 Custom Rules

Add **arbitrary authorization logic** via custom rule functions.

**Use Cases:**
- Time-based restrictions
- Rate limiting
- Content filtering
- External authorization

**Example:**
```python
from kernels.jurisdiction import RuleResult

def business_hours_only(request):
    from datetime import datetime
    hour = datetime.utcnow().hour
    if 9 <= hour < 17:
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Outside business hours")

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["tool"],
    custom_rules=[business_hours_only],
)
```

---

### 2.6 Multiple Kernel Variants

Choose the **enforcement posture** that fits your use case.

| Variant | Enforcement | Use Case |
|---------|-------------|----------|
| StrictKernel | Maximum | Production |
| PermissiveKernel | Relaxed | Development |
| EvidenceFirstKernel | Evidence required | Audit-heavy |
| DualChannelKernel | Constraints required | Structured workflows |

**Example:**
```python
from kernels import StrictKernel, PermissiveKernel

# Production
prod = StrictKernel(kernel_id="prod", policy=strict_policy)

# Development
dev = PermissiveKernel(kernel_id="dev")
```

---

### 2.7 Zero External Dependencies

KERNELS has **no external dependencies**. Uses only Python standard library.

**Benefits:**
- Simple installation
- No supply chain risk
- Minimal attack surface
- Works offline

**Standard Library Only:**
- hashlib (hashing)
- json (serialization)
- dataclasses (types)
- enum (enumerations)
- asyncio (async)

---

### 2.8 Async Support

Full **async/await support** for high-throughput scenarios.

**Example:**
```python
from kernels.async import AsyncStrictKernel

kernel = AsyncStrictKernel(kernel_id="async")

# Single request
receipt = await kernel.submit(request)

# Batch requests
receipts = await kernel.submit_batch(requests, concurrency=10)
```

---

### 2.9 SDK and Integrations

Ready-to-use **client libraries and framework integrations**.

**SDK:**
- KernelClient (sync HTTP)
- AsyncKernelClient (async HTTP)
- RequestBuilder (fluent API)
- PolicyBuilder (fluent API)
- KernelServer (HTTP server)

**Integrations:**
- FastAPI adapter
- Flask adapter
- MCP adapter

**Example:**
```python
from kernels.sdk import KernelClient, RequestBuilder

client = KernelClient("http://localhost:8080")

request = (
    RequestBuilder()
    .with_actor("agent")
    .with_intent("Read file")
    .with_tool("read_file", {"path": "/config.yaml"})
    .build()
)

receipt = client.submit(request)
```

---

### 2.10 External Verification

Audit evidence can be **verified by external parties**.

**Process:**
1. Export evidence from kernel
2. Share with auditor
3. Auditor verifies hash chain
4. No kernel access required

**Example:**
```python
# Export
evidence = kernel.export_evidence()
with open("evidence.json", "w") as f:
    json.dump(evidence, f)

# External verification (by auditor)
with open("evidence.json") as f:
    evidence = json.load(f)

from kernels.audit import replay_and_verify
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)
```

---

## 3. Advanced Features

### 3.1 Four Planes Architecture

KERNELS implements a **four-plane governance model**.

| Plane | Purpose | Components |
|-------|---------|------------|
| Governance | Policy enforcement | Kernel, Policy |
| Execution | Tool execution | Dispatcher, Tools |
| Perception | Evidence collection | Sensors, Evidence |
| Operations | Monitoring | Metrics, Logs |

---

### 3.2 Structured Proposals

Requests follow a **structured proposal schema**.

**Fields:**
- `request_id`: Unique identifier
- `actor`: Who is requesting
- `intent`: What they want to do
- `tool_call`: Specific tool and parameters
- `evidence`: Supporting evidence
- `constraints`: Scope and limits

---

### 3.3 Permit Tokens

Approved requests receive **cryptographic permit tokens**.

**Properties:**
- Signed by kernel
- Time-bounded
- Scope-limited
- Verifiable

---

### 3.4 Evidence Packets

Requests can include **evidence packets** for context.

**Types:**
- Sensor readings
- External attestations
- Prior approvals
- Context data

---

### 3.5 Halt Semantics

Kernels can be **halted** for safety.

**Properties:**
- Immediate effect
- Irreversible
- Preserves evidence
- Requires replacement

**Example:**
```python
kernel.halt()
print(kernel.state)  # KernelState.HALTED

# Cannot process requests
receipt = kernel.submit(request)  # Raises StateError
```

---

## 4. Feature Matrix

| Feature | Strict | Permissive | Evidence | Dual |
|---------|--------|------------|----------|------|
| Actor allow list | ✓ | ✓ (wildcards) | ✓ | ✓ |
| Tool allow list | ✓ | ✓ (wildcards) | ✓ | ✓ |
| Require tool_call | ✓ | Optional | ✓ | ✓ |
| Require evidence | - | - | ✓ | - |
| Require constraints | - | - | - | ✓ |
| Custom rules | ✓ | ✓ | ✓ | ✓ |
| Audit ledger | ✓ | ✓ | ✓ | ✓ |
| External verify | ✓ | ✓ | ✓ | ✓ |
| Async support | ✓ | ✓ | ✓ | ✓ |

---

## 5. Comparison

### 5.1 vs. Traditional Access Control

| Aspect | Traditional | KERNELS |
|--------|-------------|---------|
| Model | RBAC/ABAC | Jurisdiction |
| Audit | Optional | Built-in |
| Verification | Internal | External |
| State | Stateless | State machine |
| Default | Varies | Fail-closed |

### 5.2 vs. AI Guardrails

| Aspect | Guardrails | KERNELS |
|--------|------------|---------|
| Focus | Content | Actions |
| Enforcement | Probabilistic | Deterministic |
| Audit | Limited | Complete |
| Verification | None | Cryptographic |

---

## 6. Use Cases

### 6.1 AI Agent Governance

Control what AI agents can do:
- Restrict tool access
- Audit all actions
- Enforce policies

### 6.2 Compliance Automation

Meet regulatory requirements:
- Immutable audit trail
- External verification
- Policy enforcement

### 6.3 Secure Automation

Protect automated workflows:
- Fail-closed defaults
- Explicit permissions
- Complete visibility

### 6.4 Multi-Agent Systems

Coordinate multiple agents:
- Centralized policy
- Unified audit
- Consistent enforcement
