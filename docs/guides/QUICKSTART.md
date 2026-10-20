# KERNELS Quick Start Guide

**Version:** 0.1.0  
**Time to Complete:** 10 minutes

---

## 1. Installation

### Option A: Install from Source

```bash
# Clone repository
git clone https://github.com/ayais12210-hub/kernels.git
cd kernels

# Install in development mode
pip install -e .

# Verify installation
python -m kernels info
```

### Option B: Install from PyPI (Coming Soon)

```bash
pip install kernels
```

---

## 2. Your First Kernel

### Step 1: Create a Kernel

```python
from kernels import StrictKernel
from kernels.common.types import KernelConfig, VirtualClock

kernel = StrictKernel()
kernel.boot(KernelConfig(kernel_id="my-first-kernel", variant="strict", clock=VirtualClock(0)))
kernel.set_keyring({"k": b"test-secret-key-32-bytes-long123"})

print(f"Kernel ID: {kernel.config.kernel_id}")
print(f"State: {kernel.get_state()}")
```

**Output:**
```
Kernel ID: my-first-kernel
State: KernelState.IDLE
```

### Step 2: Submit a Request

A tool call needs a permit bound to the same parameters the tool will receive. `request.params` and `tool_call.params` must match.

```python
from kernels.common.types import KernelRequest, ToolCall
from kernels.permits import PermitBuilder

params = {"text": "Hello, World!"}
keyring = {"k": b"test-secret-key-32-bytes-long123"}
permit = (
    PermitBuilder()
    .issuer("operator")
    .subject("my-agent")
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
    request_id="req-001",
    ts_ms=0,
    actor="my-agent",
    intent="Say hello",
    tool_call=ToolCall(name="echo", params=dict(params)),
    params=dict(params),
)
receipt = kernel.submit(request, permit_token=permit)
print(f"Decision: {receipt.decision}")
print(f"Result: {receipt.tool_result}")
```

**Output:**
```
Decision: Decision.ALLOW
Result: Hello, World!
```

The same call without `permit_token` is `Decision.DENY` with `MISSING_PERMIT`. A permit for different parameters is denied and does not consume `max_executions`.

### Step 3: Export Evidence

```python
evidence = kernel.export_evidence()
print(f"Entries: {len(evidence.ledger_entries)}")
print(f"Root Hash: {evidence.root_hash[:16]}...")
```

A successful tool call writes two ledger entries: the intent record, then the outcome. The ledger is process memory. Export the bundle if you need to keep it. `evidence` is an object, not a dictionary.

---

## 3. Configure Policy

### Define Allowed Actors and Tools

```python
from kernels import StrictKernel, JurisdictionPolicy

# Create policy
policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],
    allowed_tools=["read_file", "write_file", "search"],
    require_tool_call=True,
    max_intent_length=500,
)

# Create kernel with policy
kernel = StrictKernel(
    kernel_id="governed-kernel",
    policy=policy,
)
```

### Test Policy Enforcement

```python
# Allowed request
allowed_request = Request(
    request_id="req-002",
    actor="agent-001",  # In allowed_actors
    intent="Read config",
    tool_call=ToolCall(name="read_file", params={"path": "/config.yaml"}),
)

receipt = kernel.submit(allowed_request)
print(f"Allowed: {receipt.decision}")  # ALLOW

# Denied request (unknown actor)
denied_request = Request(
    request_id="req-003",
    actor="unknown-agent",  # Not in allowed_actors
    intent="Read config",
    tool_call=ToolCall(name="read_file", params={"path": "/config.yaml"}),
)

receipt = kernel.submit(denied_request)
print(f"Denied: {receipt.decision}")  # DENY
```

---

## 4. Register Custom Tools

```python
from kernels.execution import ToolRegistry

# Create registry
registry = ToolRegistry()

# Register tools
@registry.register("greet")
def greet_tool(params):
    name = params.get("name", "World")
    return {"greeting": f"Hello, {name}!"}

@registry.register("add")
def add_tool(params):
    a = params.get("a", 0)
    b = params.get("b", 0)
    return {"sum": a + b}

# Create kernel with registry
kernel = StrictKernel(
    kernel_id="custom-tools-kernel",
    policy=JurisdictionPolicy(
        allowed_actors=["agent"],
        allowed_tools=["greet", "add"],
    ),
    tool_registry=registry,
)

# Use custom tool
request = Request(
    request_id="req-004",
    actor="agent",
    intent="Greet user",
    tool_call=ToolCall(name="greet", params={"name": "Alice"}),
)

receipt = kernel.submit(request)
print(receipt.result)  # {'greeting': 'Hello, Alice!'}
```

---

## 5. Verify Audit Trail

```python
from kernels.audit import replay_and_verify

# Export evidence
evidence = kernel.export_evidence()

# Verify chain integrity
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)

if is_valid:
    print("✓ Audit trail is valid")
else:
    print(f"✗ Verification failed: {errors}")
```

---

## 6. Halt the Kernel

```python
# Emergency halt
kernel.halt()

print(f"State: {kernel.state}")  # HALTED

# Requests after halt are rejected
request = Request(
    request_id="req-005",
    actor="agent",
    intent="This will fail",
    tool_call=ToolCall(name="greet", params={}),
)

try:
    kernel.submit(request)
except Exception as e:
    print(f"Error: {e}")  # Kernel is halted
```

---

## 7. Choose a Kernel Variant

```python
from kernels import (
    StrictKernel,        # Production: maximum enforcement
    PermissiveKernel,    # Development: relaxed thresholds
    EvidenceFirstKernel, # Audit-heavy: requires evidence
    DualChannelKernel,   # Structured: requires constraints
)

# For development
dev_kernel = PermissiveKernel(kernel_id="dev")

# For production
prod_kernel = StrictKernel(kernel_id="prod")

# For compliance
audit_kernel = EvidenceFirstKernel(kernel_id="audit")

# For complex workflows
workflow_kernel = DualChannelKernel(kernel_id="workflow")
```

---

## 8. Complete Example

```python
#!/usr/bin/env python3
"""Complete KERNELS example."""

from kernels import (
    StrictKernel,
    JurisdictionPolicy,
    Request,
    ToolCall,
    Decision,
)
from kernels.execution import ToolRegistry
from kernels.audit import replay_and_verify

# 1. Create tool registry
registry = ToolRegistry()

@registry.register("calculate")
def calculate(params):
    op = params.get("operation")
    a = params.get("a", 0)
    b = params.get("b", 0)
    
    if op == "add":
        return {"result": a + b}
    elif op == "multiply":
        return {"result": a * b}
    else:
        raise ValueError(f"Unknown operation: {op}")

# 2. Create policy
policy = JurisdictionPolicy(
    allowed_actors=["calculator-agent"],
    allowed_tools=["calculate"],
    require_tool_call=True,
)

# 3. Create kernel
kernel = StrictKernel(
    kernel_id="calculator-kernel",
    policy=policy,
    tool_registry=registry,
)

# 4. Submit requests
requests = [
    Request(
        request_id="calc-001",
        actor="calculator-agent",
        intent="Add 5 and 3",
        tool_call=ToolCall(
            name="calculate",
            params={"operation": "add", "a": 5, "b": 3}
        ),
    ),
    Request(
        request_id="calc-002",
        actor="calculator-agent",
        intent="Multiply 4 and 7",
        tool_call=ToolCall(
            name="calculate",
            params={"operation": "multiply", "a": 4, "b": 7}
        ),
    ),
]

for request in requests:
    receipt = kernel.submit(request)
    print(f"{request.intent}: {receipt.result}")

# 5. Verify audit trail
evidence = kernel.export_evidence()
is_valid, _ = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)
print(f"\nAudit valid: {is_valid}")
print(f"Total entries: {len(evidence['ledger_entries'])}")
```

**Output:**
```
Add 5 and 3: {'result': 8}
Multiply 4 and 7: {'result': 28}

Audit valid: True
Total entries: 2
```

---

## 9. Next Steps

| Resource | Description |
|----------|-------------|
| [Framework Guide](FRAMEWORK.md) | Deep dive into concepts |
| [Cookbook](COOKBOOK.md) | Practical recipes |
| [API Reference](../sdk/API.md) | Complete API docs |
| [Examples](/examples/) | Runnable examples |
| [Playbook](../operations/PLAYBOOK.md) | Operations guide |

---

## 10. Getting Help

- **Documentation:** `/docs/` directory
- **Examples:** `/examples/` directory
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
