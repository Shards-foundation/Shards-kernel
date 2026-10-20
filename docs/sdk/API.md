# KERNELS API Reference

**Version:** 0.1.0  
**Classification:** Reference  
**Last Updated:** October 2026

Import the supported surface from `kernels` (re-exported from `kernels.api`). A tool call is denied unless `submit` is given a permit whose `params` are the parameters that run. `request.params` and `tool_call.params` must be the same contents.

---

## 1. Core Types

### 1.1 KernelRequest

```python
@dataclass(frozen=True)
class KernelRequest:
    request_id: str
    ts_ms: int
    actor: str
    intent: str
    tool_call: Optional[ToolCall] = None
    params: dict[str, Any] = {}
    evidence: Optional[str] = None
```

`Request` is an alias of `KernelRequest`. `evidence` is one string. Dual-channel constraints live inside `params["constraints"]`, and that same dictionary is the tool-call parameters when a tool runs.

```python
from kernels import KernelRequest, ToolCall

params = {"text": "hello"}
request = KernelRequest(
    request_id="req-001",
    ts_ms=0,
    actor="my-agent",
    intent="Echo hello",
    tool_call=ToolCall(name="echo", params=dict(params)),
    params=dict(params),
)
```

### 1.2 KernelReceipt

```python
@dataclass(frozen=True)
class KernelReceipt:
    request_id: str
    status: ReceiptStatus          # ACCEPTED, REJECTED, FAILED
    state_from: KernelState
    state_to: KernelState
    ts_ms: int
    decision: Decision             # ALLOW, DENY, HALT
    error: Optional[str] = None
    evidence_hash: Optional[str] = None
    tool_result: Optional[Any] = None
```

`Receipt` is an alias of `KernelReceipt`. The tool value is `tool_result`.

```python
receipt = kernel.submit(request, permit_token=permit)
if receipt.decision == Decision.ALLOW:
    print(receipt.tool_result)
else:
    print(receipt.error)
```

### 1.3 ToolCall

```python
@dataclass(frozen=True)
class ToolCall:
    name: str
    params: dict[str, Any]
```

### 1.4 Decision and KernelState

`Decision` is `ALLOW`, `DENY`, or `HALT`.

`KernelState` is `BOOTING`, `IDLE`, `VALIDATING`, `ARBITRATING`, `EXECUTING`, `AUDITING`, `COMPLETED`, `HALTED`. A successful tool call visits `COMPLETED` and then returns to `IDLE`. `HALTED` is the only terminal state.

### 1.5 KernelConfig

```python
@dataclass
class KernelConfig:
    kernel_id: str
    variant: str
    fail_closed: bool = True
    require_jurisdiction: bool = True
    require_audit: bool = True
    clock: VirtualClock
    hash_alg: str = "sha256"
    max_param_bytes: int = 65536
    max_intent_length: int = 4096
    jurisdiction: str = "default"
    allow_insecure_unpermitted_execution: bool = False
```

`fail_closed=False` does not authorise an ambiguous request. `allow_insecure_unpermitted_execution` skips the permit on a non-strict kernel only. `StrictKernel` forces it off. The permit's `jurisdiction` must equal `KernelConfig.jurisdiction`.

---

## 2. Kernel Classes

Construct a variant, then `boot` it. `submit(request, permit_token=None)` returns a `KernelReceipt`. `halt(reason)` requires a reason and is irrevocable. `export_evidence()` returns an `EvidenceBundle`, not a dictionary. `get_state()` returns the current `KernelState`. `set_keyring` and `set_policy` install the HMAC keys and the jurisdiction policy.

```python
from kernels import (
    Decision,
    JurisdictionPolicy,
    KernelConfig,
    KernelRequest,
    PermitBuilder,
    StrictKernel,
    ToolCall,
    VirtualClock,
)

kernel = StrictKernel()
kernel.boot(KernelConfig(kernel_id="prod-001", variant="strict", clock=VirtualClock(0)))
kernel.set_keyring({"k": b"test-secret-key-32-bytes-long123"})
kernel.set_policy(JurisdictionPolicy(
    allowed_actors=frozenset({"agent-001"}),
    allowed_tools=frozenset({"echo"}),
))

params = {"text": "hello"}
keyring = {"k": b"test-secret-key-32-bytes-long123"}
permit = (
    PermitBuilder()
    .issuer("operator")
    .subject("agent-001")
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
    actor="agent-001",
    intent="Echo hello",
    tool_call=ToolCall(name="echo", params=dict(params)),
    params=dict(params),
)
receipt = kernel.submit(request, permit_token=permit)
assert receipt.decision == Decision.ALLOW
assert receipt.tool_result == "hello"
```

`PermissiveKernel` allows intent-only requests when the policy says so. `EvidenceFirstKernel` denies a request whose `evidence` string is missing or blank. `DualChannelKernel` denies a request whose `params` omit a `constraints` dictionary with `scope`, `non_goals`, and `success_criteria`. A tool call on every variant still needs a permit unless the non-strict insecure flag is set.

```python
from kernels import DualChannelKernel, EvidenceFirstKernel, KernelConfig, KernelRequest, VirtualClock

evidence_kernel = EvidenceFirstKernel()
evidence_kernel.boot(KernelConfig(
    kernel_id="audit-001", variant="evidence-first", clock=VirtualClock(0),
))

dual = DualChannelKernel()
dual.boot(KernelConfig(
    kernel_id="workflow-001", variant="dual-channel", clock=VirtualClock(0),
))
constraints = {
    "constraints": {
        "scope": "Executive summary only",
        "non_goals": ["Do not include financials"],
        "success_criteria": ["Under 200 words"],
    }
}
dual_request = KernelRequest(
    request_id="req-001",
    ts_ms=0,
    actor="agent",
    intent="Summarise the document",
    params=constraints,
)
```

The dual-channel example above is intent-only. Add a `ToolCall` whose `params` equal `constraints` and a permit for that object before a tool will run.

---

## 3. Permits

`PermitBuilder` signs an HMAC permit with a key from the kernel keyring. The permit `action` is the tool name. `params` must contain every parameter the call will use, with the same values. `max_executions` counts successful intent records. A denial does not consume that budget.

Implemented constraint keys are `forbidden_params`, `require_evidence`, and `max_time_ms`. `max_memory_mb` and `allowed_domains` are rejected as `CONSTRAINT_UNIMPLEMENTED`. Any other key is `CONSTRAINT_UNKNOWN`.

---

## 4. Policy

```python
@dataclass(frozen=True)
class JurisdictionPolicy:
    allowed_actors: FrozenSet[str]
    allowed_tools: FrozenSet[str]
    allowed_states: FrozenSet[KernelState]
    required_fields: FrozenSet[str]
    max_param_bytes: int = 65536
    max_intent_length: int = 4096
    allow_intent_only: bool = False
```

`JurisdictionPolicy.default()` allows `"*"` for actors and tools. `JurisdictionPolicy.strict()` allows nobody. There is no `require_tool_call` or `custom_rules` field.

```python
from kernels import JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=frozenset({"agent-001", "agent-002"}),
    allowed_tools=frozenset({"echo", "add"}),
    max_intent_length=500,
)
kernel.set_policy(policy)
```

`PolicyBuilder` in `kernels.sdk` produces the same object. `require_tool_call(False)` sets `allow_intent_only`. `with_custom_rule` raises when `build()` is called.

---

## 5. Audit

`kernel.export_evidence()` returns an `EvidenceBundle` with `ledger_entries`, `root_hash`, `exported_at_ms`, `kernel_id`, and `variant`. The reference ledger is process memory. It does not write a file and does not fsync.

A successful tool call appends two entries: `audit_phase="intent"` before the tool runs, then `audit_phase="outcome"`. `replay_and_verify(entries, expected_root_hash)` returns `(is_valid, errors)`.

```python
from kernels.audit import replay_and_verify
from kernels.common.codec import audit_entry_to_dict

bundle = kernel.export_evidence()
entries = [audit_entry_to_dict(entry) for entry in bundle.ledger_entries]
is_valid, errors = replay_and_verify(entries, bundle.root_hash)
```

`load_ledger` verifies that chain before installing entries. A broken chain halts the kernel.

---

## 6. Async

`AsyncStrictKernel`, `AsyncPermissiveKernel`, `AsyncEvidenceFirstKernel`, and `AsyncDualChannelKernel` wrap the synchronous kernels. `await kernel.submit(request, permit_token=permit)` uses the same checks. `await kernel.halt(reason)` halts the underlying kernel. `AsyncDispatcher.dispatch` does not run a tool.

```python
from kernels.async_support.async_kernel import AsyncStrictKernel

kernel = AsyncStrictKernel("async-001")
kernel.set_keyring(keyring)
receipt = await kernel.submit(request, permit_token=permit)
```

`submit_batch(kernel, requests, permits)` submits one request at a time on the kernel lock.

---

## 7. SDK

`KernelClient(base_url)` posts to a `KernelServer`. `submit(request, permit_token=permit)` sends the permit. `health`, `status`, and `evidence` read the remote kernel. Denial is a receipt, not an exception. A transport failure raises `KernelError`.

```python
from kernels.sdk import KernelClient, KernelServer

server = KernelServer(kernel, host="127.0.0.1", port=8080)
client = KernelClient("http://127.0.0.1:8080")
receipt = client.submit(request, permit_token=permit)
```

`RequestBuilder` copies tool parameters onto `request.params`. Evidence identifiers are joined into one string.

```python
from kernels.sdk import RequestBuilder

request = (
    RequestBuilder()
    .with_actor("my-agent")
    .with_intent("Echo hello")
    .with_tool("echo", {"text": "hello"})
    .build()
)
```

HTTP adapters accept the same body: `request_id`, `actor`, `intent`, `tool_call`, `params`, and `permit`.

```python
from kernels.integrations import create_fastapi_app, create_flask_app
from kernels.integrations.mcp_adapter import MCPAdapter

fastapi_app = create_fastapi_app(kernel)
flask_app = create_flask_app(kernel)
adapter = MCPAdapter(kernel, actor="mcp-agent")
```

---

## 8. Exceptions

`submit` returns `DENY` for a policy or permit failure. It raises `StateError` when the kernel is not booted or is halted. An unexpected exception during processing halts the kernel and is re-raised.

```
KernelError
├── BootError
├── StateError
├── JurisdictionError
├── AmbiguityError
├── ToolError
├── AuditError
└── ValidationError
```

```python
from kernels import KernelError, StateError

try:
    receipt = kernel.submit(request, permit_token=permit)
except StateError as exc:
    print(exc)
except KernelError as exc:
    print(exc)
```

---

## 9. Version

```python
from kernels import __version__
print(__version__)  # "0.1.0"
```

The hash algorithm is SHA-256. The default maximum intent length is 4096 characters. The default parameter budget is 65536 bytes.
