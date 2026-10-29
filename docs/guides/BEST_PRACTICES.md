# KERNELS Best Practices

**Version:** 0.1.0  
**Classification:** Guide  
**Last Updated:** January 2025

---

## 1. Overview

This guide provides best practices for deploying and operating KERNELS in production environments.

---

## 2. Design Principles

### 2.1 Fail Closed

**Always design for fail-closed behavior.** When in doubt, deny.

```python
# Good: Explicit allow list
policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],  # Only these
    allowed_tools=["read_file", "search"],       # Only these
)

# Bad: Implicit allow all
policy = JurisdictionPolicy(
    allowed_actors=["*"],  # Dangerous in production
    allowed_tools=["*"],   # Dangerous in production
)
```

### 2.2 Least Privilege

**Grant minimum necessary permissions.**

```python
# Good: Minimal permissions
policy = JurisdictionPolicy(
    allowed_actors=["data-reader-agent"],
    allowed_tools=["read_file"],  # Only read, not write
)

# Bad: Excessive permissions
policy = JurisdictionPolicy(
    allowed_actors=["data-reader-agent"],
    allowed_tools=["read_file", "write_file", "delete_file", "execute"],
)
```

### 2.3 Defense in Depth

**Layer multiple controls.**

```python
# Layer 1: Actor restriction
# Layer 2: Tool restriction
# Layer 3: Custom rules
# Layer 4: Tool-level validation

def time_restricted(request):
    hour = datetime.utcnow().hour
    if 9 <= hour < 17:
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Outside hours")

def rate_limited(request):
    if check_rate_limit(request.actor):
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Rate limited")

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["tool"],
    custom_rules=[time_restricted, rate_limited],
)
```

---

## 3. Configuration Best Practices

### 3.1 Use Explicit Configuration

**Never rely on defaults in production.**

```python
# Good: Explicit configuration
policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
    require_tool_call=True,
    max_intent_length=500,
)

# Bad: Relying on defaults
policy = JurisdictionPolicy()  # Uses defaults
```

### 3.2 Externalize Configuration

**Keep configuration separate from code.**

```yaml
# config/production.yaml
policy:
  allowed_actors:
    - agent-001
    - agent-002
  allowed_tools:
    - read_file
    - search
  require_tool_call: true
  max_intent_length: 500
```

```python
# Load from file
with open("config/production.yaml") as f:
    config = yaml.safe_load(f)

policy = JurisdictionPolicy(**config["policy"])
```

### 3.3 Use Environment-Specific Configs

**Different configs for different environments.**

```
config/
├── development.yaml   # Permissive for dev
├── staging.yaml       # Moderate for testing
└── production.yaml    # Strict for prod
```

```python
import os

env = os.environ.get("ENVIRONMENT", "development")
config_path = f"config/{env}.yaml"
```

---

## 4. Security Best Practices

### 4.1 Secure Kernel IDs

**Use unique, non-guessable kernel IDs.**

```python
import uuid

# Good: Unique ID
kernel_id = f"kernel-{uuid.uuid4().hex[:8]}"

# Bad: Predictable ID
kernel_id = "kernel-1"
```

### 4.2 Protect API Keys

**Never hardcode API keys.**

```python
import os

# Good: From environment
api_key = os.environ.get("KERNELS_API_KEY")

# Bad: Hardcoded
api_key = "REPLACE_WITH_A_REAL_SECRET_FROM_YOUR_SECRET_STORE"
```

### 4.3 Validate All Inputs

**Validate before processing.**

```python
def validate_request(request: Request) -> list[str]:
    errors = []
    
    if not request.request_id:
        errors.append("request_id required")
    if not request.actor:
        errors.append("actor required")
    if not request.intent:
        errors.append("intent required")
    if len(request.intent) > 10000:
        errors.append("intent too long")
    
    return errors
```

### 4.4 Sanitize Logs

**Remove sensitive data from logs.**

```python
def sanitize_for_logging(request: Request) -> dict:
    return {
        "request_id": request.request_id,
        "actor": request.actor,
        "intent": request.intent[:100] + "...",  # Truncate
        "tool": request.tool_call.name if request.tool_call else None,
        # Don't log params - may contain secrets
    }
```

---

## 5. Operational Best Practices

### 5.1 Monitor Kernel State

**Always monitor kernel state.**

```python
import time

def monitor_kernel(kernel, interval=60):
    while True:
        state = kernel.state
        if state.value == "HALTED":
            alert("Kernel halted!")
        log_metric("kernel_state", state.value)
        time.sleep(interval)
```

### 5.2 Export Evidence Regularly

**Don't let evidence accumulate unbounded.**

```python
import schedule

def export_and_archive():
    evidence = kernel.export_evidence()
    archive_path = f"evidence/{datetime.now().isoformat()}.json"
    with open(archive_path, "w") as f:
        json.dump(evidence, f)

schedule.every().hour.do(export_and_archive)
```

### 5.3 Verify Audit Chain

**Regularly verify audit integrity.**

```python
def verify_audit():
    evidence = kernel.export_evidence()
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    if not is_valid:
        alert("Audit chain verification failed!")
        for error in errors:
            log_error(error)
    
    return is_valid

# Run daily
schedule.every().day.at("00:00").do(verify_audit)
```

### 5.4 Plan for Kernel Replacement

**Kernels are designed to be replaced, not restarted.**

```python
def replace_kernel(old_kernel, policy):
    # Export evidence from old kernel
    evidence = old_kernel.export_evidence()
    archive_evidence(evidence)
    
    # Create new kernel
    new_kernel = StrictKernel(
        kernel_id=f"kernel-{int(time.time())}",
        policy=policy,
    )
    
    return new_kernel
```

---

## 6. Performance Best Practices

### 6.1 Use Async for High Throughput

**Use async kernel for concurrent requests.**

```python
from kernels.async import AsyncStrictKernel

kernel = AsyncStrictKernel(kernel_id="async-prod")

async def handle_requests(requests):
    tasks = [kernel.submit(req) for req in requests]
    return await asyncio.gather(*tasks)
```

### 6.2 Batch Operations

**Batch requests when possible.**

```python
# Good: Batch submission
receipts = await kernel.submit_batch(requests, concurrency=10)

# Less efficient: Sequential
receipts = []
for request in requests:
    receipt = await kernel.submit(request)
    receipts.append(receipt)
```

### 6.3 Set Appropriate Timeouts

**Configure timeouts for your workload.**

```python
# Short timeout for fast tools
fast_registry.register("lookup", lookup_fn, timeout=5.0)

# Longer timeout for slow tools
slow_registry.register("analyze", analyze_fn, timeout=60.0)
```

---

## 7. Testing Best Practices

### 7.1 Test Policy Enforcement

**Verify policy denies what it should.**

```python
def test_policy_denies_unknown_actor():
    policy = JurisdictionPolicy(allowed_actors=["known-agent"])
    kernel = StrictKernel(kernel_id="test", policy=policy)
    
    request = Request(
        request_id="test-001",
        actor="unknown-agent",  # Not in list
        intent="Test",
        tool_call=ToolCall(name="tool", params={}),
    )
    
    receipt = kernel.submit(request)
    assert receipt.decision == Decision.DENY
```

### 7.2 Test Edge Cases

**Test boundary conditions.**

```python
def test_max_intent_length():
    policy = JurisdictionPolicy(
        allowed_actors=["agent"],
        allowed_tools=["tool"],
        max_intent_length=100,
    )
    kernel = StrictKernel(kernel_id="test", policy=policy)
    
    # Exactly at limit - should pass
    request = Request(
        request_id="test-001",
        actor="agent",
        intent="x" * 100,
        tool_call=ToolCall(name="tool", params={}),
    )
    receipt = kernel.submit(request)
    assert receipt.decision == Decision.ALLOW
    
    # Over limit - should fail
    request = Request(
        request_id="test-002",
        actor="agent",
        intent="x" * 101,
        tool_call=ToolCall(name="tool", params={}),
    )
    receipt = kernel.submit(request)
    assert receipt.decision == Decision.DENY
```

### 7.3 Test Audit Integrity

**Verify audit chain is valid after operations.**

```python
def test_audit_integrity():
    kernel = StrictKernel(kernel_id="test", policy=policy)
    
    # Submit several requests
    for i in range(10):
        kernel.submit(create_request(i))
    
    # Verify audit chain
    evidence = kernel.export_evidence()
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    assert is_valid
    assert len(errors) == 0
```

---

## 8. Deployment Best Practices

### 8.1 Use Health Checks

**Configure health checks for orchestration.**

```yaml
# Kubernetes
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

### 8.2 Use Graceful Shutdown

**Handle shutdown signals properly.**

```python
import signal
import sys

def shutdown_handler(signum, frame):
    print("Shutting down...")
    evidence = kernel.export_evidence()
    save_evidence(evidence)
    server.stop()
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)
```

### 8.3 Use Container Best Practices

**Follow container best practices.**

```dockerfile
# Use specific version
FROM python:3.12-slim

# Non-root user
RUN useradd -m kernels
USER kernels

# Copy only what's needed
COPY --chown=kernels:kernels . /app
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir -e .

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost:8080/health || exit 1

# Run
CMD ["python", "-m", "kernels.sdk.server"]
```

---

## 9. Documentation Best Practices

### 9.1 Document Policies

**Document why policies exist.**

```yaml
# policy.yaml
policy:
  # Only approved agents can submit requests
  # See: SECURITY-001 for approval process
  allowed_actors:
    - agent-001  # Data processing agent
    - agent-002  # Search agent
  
  # Only safe tools are allowed
  # See: SECURITY-002 for tool review process
  allowed_tools:
    - read_file   # Read-only, safe
    - search      # Read-only, safe
    # write_file  # Disabled per SECURITY-003
```

### 9.2 Document Decisions

**Document architectural decisions.**

```markdown
# ADR-001: Fail-Closed Default

## Status
Accepted

## Context
We need to decide the default behavior when policy is ambiguous.

## Decision
Default to DENY when policy doesn't explicitly allow.

## Consequences
- More secure by default
- May require more explicit configuration
- Reduces risk of unintended access
```

---

## 10. Checklist

### 10.1 Pre-Production Checklist

- [ ] Explicit policy configuration
- [ ] No wildcards in production policy
- [ ] API keys from environment
- [ ] Health checks configured
- [ ] Monitoring enabled
- [ ] Alerting configured
- [ ] Evidence archival scheduled
- [ ] Audit verification scheduled
- [ ] Graceful shutdown handled
- [ ] Security review completed

### 10.2 Ongoing Operations Checklist

- [ ] Monitor kernel state daily
- [ ] Verify audit chain weekly
- [ ] Archive evidence monthly
- [ ] Review policies quarterly
- [ ] Update dependencies monthly
- [ ] Security scan weekly
- [ ] Capacity review quarterly
