# KERNELS Cookbook

**Version:** 0.1.0  
**Classification:** Developer Guide  
**Last Updated:** October 2026

---

## 1. Overview

These recipes use the installed API. Boot a kernel, set a keyring, and pass a permit whose parameters are the parameters that run. `request.params` and `tool_call.params` must match. `receipt.tool_result` is the tool value. `export_evidence()` returns an `EvidenceBundle`.

The snippets below share this setup:

```python
from kernels import (
    JurisdictionPolicy,
    KernelConfig,
    KernelRequest,
    PermitBuilder,
    StrictKernel,
    ToolCall,
    VirtualClock,
)

KEYRING = {"k": b"test-secret-key-32-bytes-long123"}

def boot(kernel_id="cookbook", variant_cls=StrictKernel, variant="strict"):
    kernel = variant_cls()
    kernel.boot(KernelConfig(
        kernel_id=kernel_id,
        variant=variant,
        clock=VirtualClock(0),
    ))
    kernel.set_keyring(KEYRING)
    return kernel

def permit_for(action, params, subject="agent"):
    return (
        PermitBuilder()
        .issuer("operator")
        .subject(subject)
        .jurisdiction("default")
        .action(action)
        .params(params)
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .proposal_hash(f"proposal-{action}")
        .build(KEYRING, "k")
    )

def call(kernel, request_id, actor, intent, tool, params, evidence=None):
    request = KernelRequest(
        request_id=request_id,
        ts_ms=0,
        actor=actor,
        intent=intent,
        tool_call=ToolCall(name=tool, params=dict(params)),
        params=dict(params),
        evidence=evidence,
    )
    return kernel.submit(
        request,
        permit_token=permit_for(tool, params, subject=actor),
    )
```

---

## 2. Basic Recipes

### Recipe 2.1: Create a kernel

```python
kernel = boot("my-kernel")
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"my-agent"}),
    allowed_tools=frozenset({"echo"}),
))
print(kernel.get_state())  # KernelState.IDLE
```

### Recipe 2.2: Submit a tool call

```python
receipt = call(
    kernel,
    "req-001",
    "my-agent",
    "Say hello",
    "echo",
    {"text": "Hello"},
)
print(receipt.decision)       # Decision.ALLOW
print(receipt.tool_result)    # Hello
```

The same request without `permit_token` is `Decision.DENY` and `MISSING_PERMIT`. A permit for different parameters is denied and does not consume `max_executions`.

### Recipe 2.3: Register a tool

```python
def read_file(path: str) -> str:
    return f"contents of {path}"

kernel._dispatcher.registry.register("read_file", read_file, "Read a file")
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"my-agent"}),
    allowed_tools=frozenset({"read_file"}),
))
receipt = call(
    kernel, "req-read", "my-agent", "Read the config",
    "read_file", {"path": "/config.yaml"},
)
print(receipt.tool_result)
```

### Recipe 2.4: Export evidence

```python
bundle = kernel.export_evidence()
print(bundle.kernel_id)
print(len(bundle.ledger_entries))  # two entries per successful tool call
print(bundle.root_hash)
```

The ledger is process memory. Export the bundle if you need to keep it. A crash drops entries that were not exported.

### Recipe 2.5: Verify evidence

```python
from kernels.audit import replay_and_verify
from kernels.common.codec import audit_entry_to_dict

entries = [audit_entry_to_dict(entry) for entry in bundle.ledger_entries]
is_valid, errors = replay_and_verify(entries, bundle.root_hash)
print(is_valid, errors)
```

---

## 3. Policy Recipes

### Recipe 3.1: Several actors

```python
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"sales-agent", "support-agent"}),
    allowed_tools=frozenset({"echo"}),
    max_intent_length=500,
))
```

An actor or tool outside those sets is denied before the tool runs.

### Recipe 3.2: There is no custom-rule field

`JurisdictionPolicy` checks actors, tools, parameter size, intent length, and tool-call shape. `PolicyBuilder.with_custom_rule(...).build()` raises `ValueError`. Add a check in front of `submit`, or deny inside the tool and let the kernel record the failure. Do not pass `custom_rules=` to `JurisdictionPolicy`.

### Recipe 3.3: Clock and permit window

The permit is valid from `valid_from_ms` until `valid_until_ms` on the kernel clock, not on the wall clock.

```python
kernel = boot("timed")
print(kernel.config.clock.now_ms())  # 0
# A permit with valid_from_ms=1_000 is denied until the clock reaches that time.
kernel.config.clock.advance(1_000)
```

### Recipe 3.4: Budgets the kernel actually enforces

`max_param_bytes` and `max_intent_length` are policy fields. `max_executions` on the permit is the execution budget. A denial does not consume it. There is no built-in requests-per-second limiter.

---

## 4. Variant Recipes

### Recipe 4.1: Evidence-first

```python
from kernels import EvidenceFirstKernel

kernel = boot("audit", EvidenceFirstKernel, "evidence-first")
receipt = call(
    kernel, "req-ev", "agent", "Echo with evidence",
    "echo", {"text": "hello"},
    evidence="ticket-42",
)
```

A missing or blank `evidence` string is denied even when the permit is valid.

### Recipe 4.2: Dual-channel

Constraints are a dictionary inside `params`. The tool call must carry the same dictionary. This recipe is intent-only, so it needs no permit:

```python
from kernels import DualChannelKernel

kernel = boot("dual", DualChannelKernel, "dual-channel")
params = {
    "constraints": {
        "scope": "Summary only",
        "non_goals": ["No financials"],
        "success_criteria": ["Under 200 words"],
    }
}
request = KernelRequest(
    request_id="req-dual",
    ts_ms=0,
    actor="agent",
    intent="Summarise the document",
    params=params,
)
receipt = kernel.submit(request)
```

### Recipe 4.3: Which variant

| Need | Variant |
| --- | --- |
| Production tool calls | `StrictKernel` |
| Intent-only development | `PermissiveKernel` |
| Evidence required | `EvidenceFirstKernel` |
| Scope, non-goals, success criteria | `DualChannelKernel` |

`StrictKernel` ignores `allow_insecure_unpermitted_execution`. The other variants honour it. That flag skips the permit. It does not allow `request.params` to differ from `tool_call.params`, and it does not allow an ambiguous request.

---

## 5. Integration Recipes

### Recipe 5.1: FastAPI

```python
from kernels.integrations import create_fastapi_app

app = create_fastapi_app(kernel)
```

`POST /submit` takes JSON with `request_id`, `actor`, `intent`, `tool_call`, `params`, and `permit`. The permit is the field mapping of a `PermitToken`. `params` must equal `tool_call.params`.

### Recipe 5.2: Flask

```python
from kernels.integrations import create_flask_app

app = create_flask_app(kernel)
client = app.test_client()
response = client.post("/submit", json=body)
```

The body is the same shape as the FastAPI body. A denial is HTTP 200 with `"decision": "DENY"`.

### Recipe 5.3: SDK server and client

```python
from kernels.sdk import KernelClient, KernelServer

server = KernelServer(kernel, host="127.0.0.1", port=8080)
client = KernelClient(server.url)
receipt = client.submit(request, permit_token=permit)
```

The CLI (`python -m kernels`) validates and replays files. It does not call `submit`.

---

## 6. Testing Recipes

### Recipe 6.1: Unit test

```python
def test_echo_needs_a_permit():
    kernel = boot("test")
    denied = kernel.submit(KernelRequest(
        request_id="no-permit",
        ts_ms=0,
        actor="agent",
        intent="Echo hello",
        tool_call=ToolCall(name="echo", params={"text": "hello"}),
        params={"text": "hello"},
    ))
    assert denied.decision.value == "DENY"
    assert "MISSING_PERMIT" in denied.error

    allowed = call(kernel, "with-permit", "agent", "Echo hello", "echo", {"text": "hello"})
    assert allowed.tool_result == "hello"
```

### Recipe 6.2: Property tests

`tests/test_governance_properties.py` uses Hypothesis from the `dev` extra. One property is that no path reaches `EXECUTING` without a permit bound to the parameters that run.

---

## 7. Advanced Recipes

### Recipe 7.1: Several kernels

Each kernel has its own ledger, nonce registry, and halted flag. Construct one `StrictKernel` per tenant and boot it with its own `kernel_id`. Do not share one kernel across threads without external serialisation. The async wrapper holds one lock around the synchronous kernel.

### Recipe 7.2: Persistence

There is no file backend. `AuditLedger.append` returns after the entry is linked in process memory. Copy `export_evidence()` out if the record must survive the process. `implementations/storage.py` is a separate SQLite sample. The kernel does not write to it. A future backend must fsync the intent record before the tool runs.

### Recipe 7.3: Halt

```python
kernel.halt("operator stop")
```

`StateMachine.reset()` can move a bare machine back to `IDLE`. It does not clear the kernel's halted flag. A later `submit` raises `StateError`.

---

## 8. Recipe Index

| Recipe | What it does |
| --- | --- |
| 2.1 | Boot a strict kernel and set a policy |
| 2.2 | Submit a permit-bound echo |
| 2.3 | Register a tool and call it |
| 2.4 | Export the evidence bundle |
| 2.5 | Replay the hash chain |
| 3.1 | Restrict actors and tools |
| 3.2 | No custom policy callables |
| 3.3 | Advance the virtual clock |
| 3.4 | Size, intent, and execution budgets |
| 4.1 | Require an evidence string |
| 4.2 | Require dual-channel constraints |
| 4.3 | Choose a variant |
| 5.1 | FastAPI |
| 5.2 | Flask |
| 5.3 | SDK client and server |
| 6.1 | Deny, then allow |
| 6.2 | Hypothesis properties |
| 7.1 | One kernel per tenant |
| 7.2 | In-memory ledger |
| 7.3 | Irrevocable halt |
