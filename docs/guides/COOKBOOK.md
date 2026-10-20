# KERNELS Cookbook

**Version:** 0.1.0  
**Classification:** Developer Guide  
**Last Updated:** January 2025

---

## 1. Overview

This cookbook provides practical recipes for common KERNELS tasks. Each recipe is self-contained and can be adapted to your needs.

A tool call is denied unless `kernel.submit(request, permit_token=permit)` is given a permit bound to the exact parameters. `request.params` and `tool_call.params` must match. Boot with `kernel.boot(KernelConfig(...))` before submit. Working calls are in `examples/`. The sketches later in this guide still use older constructor names.

---

## 2. Basic Recipes

### Recipe 2.1: Create a Simple Kernel

**Goal:** Create and start a basic kernel instance.

```python
from kernels import StrictKernel, JurisdictionPolicy

# Define policy
policy = JurisdictionPolicy(
    allowed_actors=["my-agent"],
    allowed_tools=["echo"],
    require_tool_call=True,
)

# Create kernel
kernel = StrictKernel(
    kernel_id="my-kernel",
    policy=policy,
)

print(f"Kernel state: {kernel.state}")
# Output: Kernel state: KernelState.IDLE
```

---

### Recipe 2.2: Submit a Request

**Goal:** Submit a request and handle the response.

```python
from kernels import StrictKernel, Request, ToolCall, Decision

# Create request
request = Request(
    request_id="req-001",
    actor="my-agent",
    intent="Echo a message",
    tool_call=ToolCall(
        name="echo",
        params={"message": "Hello, World!"}
    ),
)

# Submit to kernel
receipt = kernel.submit(request)

# Handle response
if receipt.decision == Decision.ALLOW:
    print(f"Allowed! Result: {receipt.result}")
else:
    print(f"Denied: {receipt.error}")
```

---

### Recipe 2.3: Register a Tool

**Goal:** Register a custom tool for execution.

```python
from kernels import StrictKernel, JurisdictionPolicy
from kernels.execution import ToolRegistry

# Create tool registry
registry = ToolRegistry()

# Register tool
@registry.register("echo")
def echo_tool(params):
    return {"echoed": params.get("message", "")}

@registry.register("add")
def add_tool(params):
    a = params.get("a", 0)
    b = params.get("b", 0)
    return {"sum": a + b}

# Create kernel with registry
policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["echo", "add"],
)

kernel = StrictKernel(
    kernel_id="my-kernel",
    policy=policy,
    tool_registry=registry,
)
```

---

### Recipe 2.4: Export Evidence

**Goal:** Export audit evidence for external verification.

```python
import json
from kernels import StrictKernel

# Export evidence
evidence = kernel.export_evidence()

# Save to file
with open("evidence.json", "w") as f:
    json.dump(evidence, f, indent=2)

print(f"Exported {len(evidence['ledger_entries'])} entries")
print(f"Root hash: {evidence['root_hash']}")
```

---

### Recipe 2.5: Verify Evidence

**Goal:** Verify exported evidence is valid.

```python
import json
from kernels.audit import replay_and_verify

# Load evidence
with open("evidence.json", "r") as f:
    evidence = json.load(f)

# Verify
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)

if is_valid:
    print("Evidence is valid!")
else:
    print(f"Verification failed: {errors}")
```

---

## 3. Policy Recipes

### Recipe 3.1: Multi-Actor Policy

**Goal:** Allow multiple actors with different permissions.

```python
from kernels import StrictKernel, JurisdictionPolicy

# Policy allowing multiple actors
policy = JurisdictionPolicy(
    allowed_actors=[
        "agent-reader",
        "agent-writer",
        "agent-admin",
    ],
    allowed_tools=[
        "read_file",
        "write_file",
        "delete_file",
    ],
)

# Note: Fine-grained per-actor permissions require custom rules
# See Recipe 3.2 for advanced policy
```

---

### Recipe 3.2: Custom Policy Rules

**Goal:** Implement custom authorization logic.

```python
from kernels import StrictKernel, JurisdictionPolicy, Request
from kernels.jurisdiction import Rule, RuleResult

# Define custom rules
def actor_tool_matrix(request: Request) -> RuleResult:
    """Restrict tools based on actor."""
    matrix = {
        "agent-reader": ["read_file"],
        "agent-writer": ["read_file", "write_file"],
        "agent-admin": ["read_file", "write_file", "delete_file"],
    }
    
    allowed_tools = matrix.get(request.actor, [])
    
    if request.tool_call and request.tool_call.name in allowed_tools:
        return RuleResult(allowed=True)
    else:
        return RuleResult(
            allowed=False,
            reason=f"Actor {request.actor} cannot use {request.tool_call.name}"
        )

# Create policy with custom rules
policy = JurisdictionPolicy(
    allowed_actors=["agent-reader", "agent-writer", "agent-admin"],
    allowed_tools=["read_file", "write_file", "delete_file"],
    custom_rules=[actor_tool_matrix],
)
```

---

### Recipe 3.3: Time-Based Policy

**Goal:** Restrict actions to specific time windows.

```python
from datetime import datetime
from kernels.jurisdiction import Rule, RuleResult

def business_hours_only(request):
    """Only allow actions during business hours."""
    now = datetime.utcnow()
    
    # Monday = 0, Sunday = 6
    is_weekday = now.weekday() < 5
    is_business_hours = 9 <= now.hour < 17
    
    if is_weekday and is_business_hours:
        return RuleResult(allowed=True)
    else:
        return RuleResult(
            allowed=False,
            reason="Actions only allowed during business hours (Mon-Fri 9-17 UTC)"
        )

# Add to policy
policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["sensitive_action"],
    custom_rules=[business_hours_only],
)
```

---

### Recipe 3.4: Rate Limiting Rule

**Goal:** Limit request rate per actor.

```python
from collections import defaultdict
import time
from kernels.jurisdiction import RuleResult

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def __call__(self, request):
        now = time.time()
        actor = request.actor
        
        # Clean old requests
        self.requests[actor] = [
            ts for ts in self.requests[actor]
            if now - ts < self.window_seconds
        ]
        
        # Check limit
        if len(self.requests[actor]) >= self.max_requests:
            return RuleResult(
                allowed=False,
                reason=f"Rate limit exceeded: {self.max_requests} per {self.window_seconds}s"
            )
        
        # Record request
        self.requests[actor].append(now)
        return RuleResult(allowed=True)

# Usage
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["api_call"],
    custom_rules=[rate_limiter],
)
```

---

## 4. Variant Recipes

### Recipe 4.1: Use Evidence-First Kernel

**Goal:** Require evidence for all requests.

```python
from kernels import EvidenceFirstKernel, Request, ToolCall

kernel = EvidenceFirstKernel(kernel_id="evidence-kernel")

# This will be DENIED (no evidence)
request_no_evidence = Request(
    request_id="req-001",
    actor="agent",
    intent="Do something",
    tool_call=ToolCall(name="action", params={}),
)

receipt = kernel.submit(request_no_evidence)
print(receipt.decision)  # DENY

# This will be evaluated (has evidence)
request_with_evidence = Request(
    request_id="req-002",
    actor="agent",
    intent="Do something",
    tool_call=ToolCall(name="action", params={}),
    evidence=["evidence-001", "evidence-002"],
)

receipt = kernel.submit(request_with_evidence)
print(receipt.decision)  # ALLOW (if policy permits)
```

---

### Recipe 4.2: Use Dual-Channel Kernel

**Goal:** Require structured constraints for all requests.

```python
from kernels import DualChannelKernel, Request, ToolCall

kernel = DualChannelKernel(kernel_id="dual-kernel")

# Request with constraints
request = Request(
    request_id="req-001",
    actor="agent",
    intent="Summarize document",
    tool_call=ToolCall(name="summarize", params={"doc_id": "123"}),
    constraints={
        "scope": "Only the executive summary section",
        "non_goals": ["Do not include financial data", "Do not quote directly"],
        "success_criteria": ["Summary under 200 words", "Captures main points"],
    },
)

receipt = kernel.submit(request)
```

---

### Recipe 4.3: Choose Kernel Variant

**Goal:** Select appropriate kernel for use case.

```python
from kernels import (
    StrictKernel,
    PermissiveKernel,
    EvidenceFirstKernel,
    DualChannelKernel,
)

def create_kernel(environment: str, use_case: str):
    """Factory function to create appropriate kernel."""
    
    if environment == "development":
        # Permissive for development
        return PermissiveKernel(kernel_id=f"dev-{use_case}")
    
    elif environment == "production":
        if use_case == "audit_heavy":
            # Evidence required for audit-heavy workloads
            return EvidenceFirstKernel(kernel_id=f"prod-{use_case}")
        
        elif use_case == "structured":
            # Dual channel for structured workflows
            return DualChannelKernel(kernel_id=f"prod-{use_case}")
        
        else:
            # Strict for general production
            return StrictKernel(kernel_id=f"prod-{use_case}")
    
    else:
        raise ValueError(f"Unknown environment: {environment}")

# Usage
kernel = create_kernel("production", "audit_heavy")
```

---

## 5. Integration Recipes

### Recipe 5.1: FastAPI Integration

**Goal:** Expose kernel via REST API.

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from kernels import StrictKernel, Request, ToolCall, Decision

app = FastAPI()
kernel = StrictKernel(kernel_id="api-kernel")

class RequestBody(BaseModel):
    request_id: str
    actor: str
    intent: str
    tool_name: str
    tool_params: dict

class ReceiptResponse(BaseModel):
    request_id: str
    decision: str
    result: dict | None
    error: str | None

@app.post("/submit", response_model=ReceiptResponse)
async def submit_request(body: RequestBody):
    request = Request(
        request_id=body.request_id,
        actor=body.actor,
        intent=body.intent,
        tool_call=ToolCall(
            name=body.tool_name,
            params=body.tool_params,
        ),
    )
    
    receipt = kernel.submit(request)
    
    return ReceiptResponse(
        request_id=receipt.request_id,
        decision=receipt.decision.value,
        result=receipt.result,
        error=receipt.error,
    )

@app.get("/health")
async def health():
    return {"status": "healthy", "kernel_state": kernel.state.value}

@app.get("/evidence")
async def get_evidence():
    return kernel.export_evidence()
```

---

### Recipe 5.2: Flask Integration

**Goal:** Expose kernel via Flask API.

```python
from flask import Flask, request, jsonify
from kernels import StrictKernel, Request, ToolCall

app = Flask(__name__)
kernel = StrictKernel(kernel_id="flask-kernel")

@app.route("/submit", methods=["POST"])
def submit_request():
    data = request.json
    
    req = Request(
        request_id=data["request_id"],
        actor=data["actor"],
        intent=data["intent"],
        tool_call=ToolCall(
            name=data["tool_name"],
            params=data.get("tool_params", {}),
        ),
    )
    
    receipt = kernel.submit(req)
    
    return jsonify({
        "request_id": receipt.request_id,
        "decision": receipt.decision.value,
        "result": receipt.result,
        "error": receipt.error,
    })

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "kernel_state": kernel.state.value})

if __name__ == "__main__":
    app.run(port=8080)
```

---

### Recipe 5.3: CLI Integration

**Goal:** Create command-line interface for kernel.

```python
import argparse
import json
from kernels import StrictKernel, Request, ToolCall

def main():
    parser = argparse.ArgumentParser(description="KERNELS CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # Submit command
    submit_parser = subparsers.add_parser("submit")
    submit_parser.add_argument("--actor", required=True)
    submit_parser.add_argument("--intent", required=True)
    submit_parser.add_argument("--tool", required=True)
    submit_parser.add_argument("--params", type=json.loads, default={})
    
    # Status command
    subparsers.add_parser("status")
    
    # Evidence command
    subparsers.add_parser("evidence")
    
    # Halt command
    subparsers.add_parser("halt")
    
    args = parser.parse_args()
    
    kernel = StrictKernel(kernel_id="cli-kernel")
    
    if args.command == "submit":
        request = Request(
            request_id=f"cli-{int(time.time())}",
            actor=args.actor,
            intent=args.intent,
            tool_call=ToolCall(name=args.tool, params=args.params),
        )
        receipt = kernel.submit(request)
        print(json.dumps({
            "decision": receipt.decision.value,
            "result": receipt.result,
            "error": receipt.error,
        }, indent=2))
    
    elif args.command == "status":
        print(f"Kernel state: {kernel.state.value}")
    
    elif args.command == "evidence":
        evidence = kernel.export_evidence()
        print(json.dumps(evidence, indent=2))
    
    elif args.command == "halt":
        kernel.halt()
        print("Kernel halted")

if __name__ == "__main__":
    main()
```

---

## 6. Testing Recipes

### Recipe 6.1: Unit Test Kernel

**Goal:** Write unit tests for kernel behavior.

```python
import unittest
from kernels import StrictKernel, Request, ToolCall, Decision

class TestKernel(unittest.TestCase):
    def setUp(self):
        self.kernel = StrictKernel(kernel_id="test-kernel")
    
    def test_valid_request_allowed(self):
        request = Request(
            request_id="test-001",
            actor="agent",
            intent="Test action",
            tool_call=ToolCall(name="test", params={}),
        )
        
        receipt = self.kernel.submit(request)
        
        self.assertEqual(receipt.decision, Decision.ALLOW)
    
    def test_unknown_actor_denied(self):
        request = Request(
            request_id="test-002",
            actor="unknown-actor",
            intent="Test action",
            tool_call=ToolCall(name="test", params={}),
        )
        
        receipt = self.kernel.submit(request)
        
        self.assertEqual(receipt.decision, Decision.DENY)
    
    def test_halt_works(self):
        self.kernel.halt()
        
        self.assertEqual(self.kernel.state.value, "HALTED")

if __name__ == "__main__":
    unittest.main()
```

---

### Recipe 6.2: Property-Based Testing

**Goal:** Use property-based testing for invariants.

```python
from hypothesis import given, strategies as st
from kernels import StrictKernel, Request, ToolCall

@given(
    actor=st.text(min_size=1, max_size=50),
    intent=st.text(min_size=1, max_size=200),
    tool_name=st.text(min_size=1, max_size=30),
)
def test_kernel_never_crashes(actor, intent, tool_name):
    """Kernel should never crash regardless of input."""
    kernel = StrictKernel(kernel_id="prop-test")
    
    request = Request(
        request_id="prop-001",
        actor=actor,
        intent=intent,
        tool_call=ToolCall(name=tool_name, params={}),
    )
    
    # Should not raise
    receipt = kernel.submit(request)
    
    # Should have valid decision
    assert receipt.decision in [Decision.ALLOW, Decision.DENY, Decision.HALT]

@given(st.integers(min_value=1, max_value=100))
def test_audit_chain_always_valid(num_requests):
    """Audit chain should always be valid."""
    kernel = StrictKernel(kernel_id="chain-test")
    
    for i in range(num_requests):
        request = Request(
            request_id=f"req-{i}",
            actor="agent",
            intent=f"Action {i}",
            tool_call=ToolCall(name="test", params={}),
        )
        kernel.submit(request)
    
    evidence = kernel.export_evidence()
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    assert is_valid, f"Chain invalid after {num_requests} requests: {errors}"
```

---

## 7. Advanced Recipes

### Recipe 7.1: Kernel Pool

**Goal:** Manage pool of kernels for load distribution.

```python
from typing import List
import random
from kernels import StrictKernel, Request

class KernelPool:
    def __init__(self, size: int):
        self.kernels: List[StrictKernel] = [
            StrictKernel(kernel_id=f"pool-{i}")
            for i in range(size)
        ]
    
    def get_kernel(self) -> StrictKernel:
        """Get a random available kernel."""
        available = [k for k in self.kernels if k.state.value == "IDLE"]
        if not available:
            raise RuntimeError("No available kernels")
        return random.choice(available)
    
    def submit(self, request: Request):
        """Submit to an available kernel."""
        kernel = self.get_kernel()
        return kernel.submit(request)
    
    def export_all_evidence(self):
        """Export evidence from all kernels."""
        return {
            k.kernel_id: k.export_evidence()
            for k in self.kernels
        }
    
    def halt_all(self):
        """Halt all kernels."""
        for kernel in self.kernels:
            kernel.halt()

# Usage
pool = KernelPool(size=4)
receipt = pool.submit(request)
```

---

### Recipe 7.2: Kernel with Persistence

**Goal:** Persist audit ledger to disk.

```python
import json
import os
from kernels import StrictKernel

class PersistentKernel:
    def __init__(self, kernel_id: str, persistence_path: str):
        self.kernel = StrictKernel(kernel_id=kernel_id)
        self.persistence_path = persistence_path
        self._load_if_exists()
    
    def _load_if_exists(self):
        """Load existing evidence if available."""
        if os.path.exists(self.persistence_path):
            with open(self.persistence_path, 'r') as f:
                evidence = json.load(f)
            # Restore ledger state
            self.kernel._ledger.restore(evidence["ledger_entries"])
    
    def submit(self, request):
        """Submit and persist."""
        receipt = self.kernel.submit(request)
        self._persist()
        return receipt
    
    def _persist(self):
        """Save current state to disk."""
        evidence = self.kernel.export_evidence()
        with open(self.persistence_path, 'w') as f:
            json.dump(evidence, f)
    
    def export_evidence(self):
        return self.kernel.export_evidence()

# Usage
kernel = PersistentKernel(
    kernel_id="persistent-001",
    persistence_path="/var/lib/kernels/evidence.json"
)
```

---

### Recipe 7.3: Metrics Collection

**Goal:** Collect and expose Prometheus metrics.

```python
from prometheus_client import Counter, Histogram, Gauge
from kernels import StrictKernel, Request, Decision

# Define metrics
REQUESTS_TOTAL = Counter(
    'kernels_requests_total',
    'Total requests processed',
    ['kernel_id', 'decision']
)

REQUEST_LATENCY = Histogram(
    'kernels_request_latency_seconds',
    'Request processing latency',
    ['kernel_id']
)

KERNEL_STATE = Gauge(
    'kernels_state',
    'Current kernel state (1=IDLE, 0=other)',
    ['kernel_id']
)

class MetricsKernel:
    def __init__(self, kernel_id: str):
        self.kernel = StrictKernel(kernel_id=kernel_id)
        self.kernel_id = kernel_id
    
    def submit(self, request: Request):
        with REQUEST_LATENCY.labels(kernel_id=self.kernel_id).time():
            receipt = self.kernel.submit(request)
        
        REQUESTS_TOTAL.labels(
            kernel_id=self.kernel_id,
            decision=receipt.decision.value
        ).inc()
        
        KERNEL_STATE.labels(kernel_id=self.kernel_id).set(
            1 if self.kernel.state.value == "IDLE" else 0
        )
        
        return receipt

# Usage
kernel = MetricsKernel(kernel_id="metrics-001")
```

---

## 8. Recipe Index

| Recipe | Category | Difficulty |
|--------|----------|------------|
| 2.1 Create Simple Kernel | Basic | Easy |
| 2.2 Submit Request | Basic | Easy |
| 2.3 Register Tool | Basic | Easy |
| 2.4 Export Evidence | Basic | Easy |
| 2.5 Verify Evidence | Basic | Easy |
| 3.1 Multi-Actor Policy | Policy | Medium |
| 3.2 Custom Policy Rules | Policy | Medium |
| 3.3 Time-Based Policy | Policy | Medium |
| 3.4 Rate Limiting | Policy | Medium |
| 4.1 Evidence-First Kernel | Variant | Easy |
| 4.2 Dual-Channel Kernel | Variant | Easy |
| 4.3 Choose Variant | Variant | Medium |
| 5.1 FastAPI Integration | Integration | Medium |
| 5.2 Flask Integration | Integration | Medium |
| 5.3 CLI Integration | Integration | Medium |
| 6.1 Unit Testing | Testing | Easy |
| 6.2 Property Testing | Testing | Hard |
| 7.1 Kernel Pool | Advanced | Hard |
| 7.2 Persistence | Advanced | Hard |
| 7.3 Metrics | Advanced | Medium |
