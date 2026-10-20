# KERNELS API Reference

**Version:** 0.1.0  
**Classification:** Reference  
**Last Updated:** October 2026

Tool calls are denied unless `submit(..., permit_token=permit)` carries a permit whose `params` are the parameters that run. `request.params` and `tool_call.params` must be the same contents. Issue that permit with `PermitBuilder` and a configured key. See `examples/02_tool_execution.py`. The class sketches below are not the installed import surface (`KernelRequest`, `KernelReceipt`, `permit_token`).

---

## 1. Core Types

### 1.1 Request

Represents a request to the kernel.

```python
@dataclass
class Request:
    request_id: str          # Unique request identifier
    actor: str               # Actor making the request
    intent: str              # Natural language intent
    tool_call: ToolCall      # Optional tool to execute
    evidence: List[str]      # Optional evidence IDs
    constraints: Dict        # Optional constraints (dual-channel)
```

**Example:**

```python
from kernels import Request, ToolCall

request = Request(
    request_id="req-001",
    actor="my-agent",
    intent="Read the configuration file",
    tool_call=ToolCall(
        name="read_file",
        params={"path": "/config.yaml"}
    ),
)
```

---

### 1.2 Receipt

Represents the kernel's response to a request.

```python
@dataclass
class Receipt:
    request_id: str          # Matching request ID
    status: str              # ACCEPTED, DENIED, INVALID, ERROR
    decision: Decision       # ALLOW, DENY, HALT
    result: Dict             # Tool execution result (if allowed)
    error: str               # Error message (if denied/error)
```

**Example:**

```python
receipt = kernel.submit(request, permit_token=permit)

if receipt.decision == Decision.ALLOW:
    print(f"Result: {receipt.tool_result}")
else:
    print(f"Denied: {receipt.error}")
```

---

### 1.3 ToolCall

Represents a tool invocation.

```python
@dataclass
class ToolCall:
    name: str                # Tool name
    params: Dict[str, Any]   # Tool parameters
```

**Example:**

```python
from kernels import ToolCall

tool_call = ToolCall(
    name="search",
    params={"query": "KERNELS documentation", "limit": 10}
)
```

---

### 1.4 Decision

Enumeration of possible decisions.

```python
class Decision(Enum):
    ALLOW = "ALLOW"   # Request permitted
    DENY = "DENY"     # Request denied
    HALT = "HALT"     # Kernel halted
```

---

### 1.5 KernelState

Enumeration of kernel states.

```python
class KernelState(Enum):
    BOOTING = "BOOTING"
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    ARBITRATING = "ARBITRATING"
    EXECUTING = "EXECUTING"
    AUDITING = "AUDITING"
    COMPLETED = "COMPLETED"
    HALTED = "HALTED"
```

---

## 2. Kernel Classes

### 2.1 StrictKernel

Maximum enforcement kernel for production use.

```python
class StrictKernel:
    def __init__(
        self,
        kernel_id: str,
        policy: JurisdictionPolicy = None,
        tool_registry: ToolRegistry = None,
    ): ...
    
    @property
    def state(self) -> KernelState: ...
    
    @property
    def kernel_id(self) -> str: ...
    
    @property
    def policy(self) -> JurisdictionPolicy: ...
    
    def submit(self, request: Request, permit_token: PermitToken = None) -> Receipt: ...
    
    def halt(self, reason: str) -> Receipt: ...
    
    def export_evidence(self) -> Dict[str, Any]: ...
```

**Example:**

```python
from kernels import StrictKernel, JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
)

kernel = StrictKernel(
    kernel_id="prod-001",
    policy=policy,
)

receipt = kernel.submit(request, permit_token=permit)
```

---

### 2.2 PermissiveKernel

Relaxed kernel for development use.

```python
class PermissiveKernel:
    # Same interface as StrictKernel
    # Allows wildcards in policy
    # Intent-only requests permitted
```

**Example:**

```python
from kernels import PermissiveKernel

kernel = PermissiveKernel(kernel_id="dev-001")
# Allows any actor, any tool by default
```

---

### 2.3 EvidenceFirstKernel

Requires evidence for all requests.

```python
class EvidenceFirstKernel:
    # Same interface as StrictKernel
    # Requires evidence field in requests
```

**Example:**

```python
from kernels import EvidenceFirstKernel, Request

kernel = EvidenceFirstKernel(kernel_id="audit-001")

request = Request(
    request_id="req-001",
    actor="agent",
    intent="Action",
    tool_call=tool_call,
    evidence=["evidence-001", "evidence-002"],  # Required
)
```

---

### 2.4 DualChannelKernel

Requires constraints for all requests.

```python
class DualChannelKernel:
    # Same interface as StrictKernel
    # Requires constraints dict in requests
```

**Example:**

```python
from kernels import DualChannelKernel, Request

kernel = DualChannelKernel(kernel_id="workflow-001")

request = Request(
    request_id="req-001",
    actor="agent",
    intent="Summarize document",
    tool_call=tool_call,
    constraints={
        "scope": "Executive summary only",
        "non_goals": ["Do not include financials"],
        "success_criteria": ["Under 200 words"],
    },
)
```

---

## 3. Policy

### 3.1 JurisdictionPolicy

Defines what the kernel permits.

```python
@dataclass
class JurisdictionPolicy:
    allowed_actors: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    require_tool_call: bool = True
    max_intent_length: int = 1000
    custom_rules: List[Callable] = field(default_factory=list)
```

**Example:**

```python
from kernels import JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],
    allowed_tools=["read_file", "write_file", "search"],
    require_tool_call=True,
    max_intent_length=500,
)
```

---

### 3.2 Custom Rules

Add custom authorization logic.

```python
from kernels.jurisdiction import RuleResult

def my_rule(request: Request) -> RuleResult:
    if condition(request):
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Condition not met")

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["tool"],
    custom_rules=[my_rule],
)
```

---

## 4. Audit

### 4.1 AuditLedger

Append-only hash-chained ledger.

```python
class AuditLedger:
    def append(self, entry: AuditEntry) -> None: ...
    
    def export(self) -> List[Dict]: ...
    
    @property
    def root_hash(self) -> str: ...
    
    @property
    def entry_count(self) -> int: ...
```

---

### 4.2 AuditEntry

Single entry in the audit ledger.

```python
@dataclass
class AuditEntry:
    request_id: str
    actor: str
    intent: str
    tool_name: str
    decision: Decision
    reason: str
    error: str
    ts_ms: int
    duration_ms: int
    prev_hash: str
    entry_hash: str
```

---

### 4.3 replay_and_verify

Verify audit chain integrity.

```python
def replay_and_verify(
    entries: List[Dict],
    expected_root_hash: str,
) -> Tuple[bool, List[str]]:
    """
    Verify audit chain integrity.
    
    Args:
        entries: List of audit entries
        expected_root_hash: Expected final hash
        
    Returns:
        Tuple of (is_valid, errors)
    """
```

**Example:**

```python
from kernels.audit import replay_and_verify

evidence = kernel.export_evidence()
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)
```

---

## 5. Async API

### 5.1 AsyncStrictKernel

Async version of StrictKernel.

```python
class AsyncStrictKernel:
    async def submit(self, request: Request) -> Receipt: ...
    
    async def halt_async(self) -> None: ...
    
    async def export_evidence_async(self) -> Dict: ...
```

**Example:**

```python
from kernels.async import AsyncStrictKernel

kernel = AsyncStrictKernel(kernel_id="async-001")
receipt = await kernel.submit(request)
```

---

### 5.2 Batch Operations

```python
from kernels.async.async_kernel import submit_batch

receipts = await submit_batch(
    kernel,
    requests,
    concurrency=10,
)
```

---

## 6. SDK

### 6.1 KernelClient

HTTP client for remote kernels.

```python
class KernelClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: str = None,
        timeout: float = 30.0,
    ): ...
    
    def submit(self, request: Request) -> Receipt: ...
    
    def health(self) -> Dict: ...
    
    def status(self) -> Dict: ...
    
    def evidence(self) -> Dict: ...
    
    def halt(self) -> Dict: ...
```

**Example:**

```python
from kernels.sdk import KernelClient

client = KernelClient("http://localhost:8080")
receipt = client.submit(request)
```

---

### 6.2 RequestBuilder

Fluent builder for requests.

```python
from kernels.sdk import RequestBuilder

request = (
    RequestBuilder()
    .with_actor("my-agent")
    .with_intent("Read file")
    .with_tool("read_file", {"path": "/config.yaml"})
    .build()
)
```

---

### 6.3 PolicyBuilder

Fluent builder for policies.

```python
from kernels.sdk import PolicyBuilder

policy = (
    PolicyBuilder()
    .allow_actors("agent-001", "agent-002")
    .allow_tools("read_file", "write_file")
    .require_tool_call()
    .build()
)
```

---

### 6.4 KernelServer

HTTP server for kernels.

```python
from kernels.sdk import KernelServer

server = KernelServer(kernel, port=8080)
server.start()
```

---

## 7. Integrations

### 7.1 FastAPI

```python
from kernels.integrations import create_fastapi_app

app = create_fastapi_app(kernel)
# Run with: uvicorn app:app
```

---

### 7.2 Flask

```python
from kernels.integrations import create_flask_app

app = create_flask_app(kernel)
# Run with: flask run
```

---

### 7.3 MCP

```python
from kernels.integrations import MCPAdapter

adapter = MCPAdapter(kernel, actor="mcp-agent")
adapter.register_tool("my_tool", handler, "Description", schema)
result = adapter.handle_tool_call(mcp_call)
```

---

## 8. Exceptions

### 8.1 Exception Hierarchy

```
KernelError
├── ValidationError
├── JurisdictionError
├── StateError
├── AuditError
└── ExecutionError
```

### 8.2 Usage

```python
from kernels import KernelError, JurisdictionError

try:
    receipt = kernel.submit(request)
except JurisdictionError as e:
    print(f"Policy violation: {e}")
except KernelError as e:
    print(f"Kernel error: {e}")
```

---

## 9. Constants

### 9.1 Version

```python
from kernels import __version__
print(__version__)  # "0.1.0"
```

### 9.2 Default Values

| Constant | Value |
|----------|-------|
| `DEFAULT_MAX_INTENT_LENGTH` | 1000 |
| `DEFAULT_TIMEOUT` | 30.0 |
| `HASH_ALGORITHM` | SHA-256 |

---

## 10. Type Hints

All public APIs include type hints:

```python
def submit(self, request: Request) -> Receipt: ...

def export_evidence(self) -> Dict[str, Any]: ...

def replay_and_verify(
    entries: List[Dict[str, Any]],
    expected_root_hash: str,
) -> Tuple[bool, List[str]]: ...
```
