# Shards-Kernel Quick Start Guide

**Version:** 0.1.0  
**Time to Complete:** 10 minutes

---

## 1. Installation

### Option A: Install from Source

```bash
# Clone repository
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel

# Install in development mode
pip install -e .

# Verify installation
python -m shards_kernel info
```

### Option B: Install the distribution

The distribution name is `shards-kernel`, and its import namespace is `shards_kernel`. An approved PyPI release is pending. Do not install the unrelated PyPI project `kernels`. Until a verified Shards-Kernel release exists, install from GitHub:

```bash
python -m pip install "git+https://github.com/Shards-foundation/Shards-kernel.git"
python -c "import shards_kernel"
```

---

## 2. Your First Kernel

### Step 1: Create a Kernel

```python
from shards_kernel import StrictKernel
from shards_kernel.common.types import KernelConfig, VirtualClock

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
from shards_kernel.common.types import KernelRequest, ToolCall
from shards_kernel.permits import PermitBuilder

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

```python
from shards_kernel import JurisdictionPolicy

kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"agent-001", "agent-002"}),
    allowed_tools=frozenset({"echo"}),
    max_intent_length=500,
))
```

An actor outside that set is denied before the tool runs. The built-in `echo` tool is allowed for `agent-001` when the permit names that subject.

## 4. Register a Tool

Handlers are called with keyword arguments. Register on the kernel's dispatcher, then issue a permit for the same parameters.

```python
def greet(name: str) -> str:
    return f"Hello, {name}!"

kernel._dispatcher.registry.register("greet", greet, "Greet someone")
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"agent"}),
    allowed_tools=frozenset({"greet"}),
))
```

## 5. Verify the Audit Trail

```python
from shards_kernel.audit import replay_and_verify
from shards_kernel.common.codec import audit_entry_to_dict

bundle = kernel.export_evidence()
entries = [audit_entry_to_dict(entry) for entry in bundle.ledger_entries]
is_valid, errors = replay_and_verify(entries, bundle.root_hash)
print(is_valid, errors)
```

## 6. Halt the Kernel

```python
from shards_kernel.common.errors import StateError

kernel.halt("operator stop")
print(kernel.get_state())  # KernelState.HALTED
try:
    kernel.submit(request, permit_token=permit)
except StateError as exc:
    print(exc)
```

Resetting the inner state machine does not resume a halted kernel.

## 7. Choose a Variant

Boot `StrictKernel` for production. `PermissiveKernel` can allow intent-only requests. `EvidenceFirstKernel` requires a non-empty `evidence` string. `DualChannelKernel` requires `params["constraints"]` with `scope`, `non_goals`, and `success_criteria`. A tool call on every variant needs a permit unless a non-strict kernel sets `allow_insecure_unpermitted_execution`.

## 8. Where to go next

Working programs are in `examples/`. Recipes are in the cookbook. The API reference lists the installed types.

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
