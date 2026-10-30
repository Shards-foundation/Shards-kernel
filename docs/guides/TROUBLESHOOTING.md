# Shards-Kernel Troubleshooting Guide

**Version:** 0.1.0  
**Classification:** Operations  
**Last Updated:** January 2025

---

## 1. Overview

This guide helps diagnose and resolve common issues with Shards-Kernel.

---

## 2. Quick Diagnostics

### 2.1 Health Check

```bash
# Check if kernel is running
curl http://localhost:8080/health

# Expected response
{"status": "healthy", "kernel_state": "IDLE"}
```

### 2.2 Status Check

```bash
# Get kernel status
curl http://localhost:8080/status

# Expected response
{"kernel_id": "prod-001", "state": "IDLE"}
```

### 2.3 Python Check

```python
from shards_kernel import StrictKernel

kernel = StrictKernel(kernel_id="test")
print(f"State: {kernel.state}")  # Should print: State: KernelState.IDLE
```

---

## 3. Common Issues

### 3.1 Installation Issues

#### Issue: ModuleNotFoundError: No module named 'shards_kernel'

**Cause:** Package not installed or wrong Python environment.

**Solution:**
```bash
# Verify Python version
python --version  # Should be 3.11+

# Install package
pip install -e .

# Verify installation
python -c "import shards_kernel; print(shards_kernel.__version__)"
```

#### Issue: Python version not supported

**Cause:** Using Python < 3.11.

**Solution:**
```bash
# Install Python 3.11+
sudo apt install python3.11

# Use correct Python
python3.11 -m pip install -e .
```

---

### 3.2 Request Issues

#### Issue: Request denied - Actor not allowed

**Symptom:**
```json
{"decision": "DENY", "error": "Actor unknown-agent not allowed"}
```

**Cause:** Actor not in `allowed_actors` list.

**Solution:**
```python
# Check policy
print(kernel.policy.allowed_actors)

# Add actor to policy
policy = JurisdictionPolicy(
    allowed_actors=["unknown-agent", ...],  # Add the actor
    ...
)
```

#### Issue: Request denied - Tool not allowed

**Symptom:**
```json
{"decision": "DENY", "error": "Tool dangerous_tool not allowed"}
```

**Cause:** Tool not in `allowed_tools` list.

**Solution:**
```python
# Check policy
print(kernel.policy.allowed_tools)

# Add tool to policy
policy = JurisdictionPolicy(
    allowed_tools=["dangerous_tool", ...],  # Add the tool
    ...
)
```

#### Issue: Request denied - tool_call required

**Symptom:**
```json
{"decision": "DENY", "error": "tool_call is required"}
```

**Cause:** Request missing tool_call and policy requires it.

**Solution:**
```python
# Option 1: Add tool_call to request
request = Request(
    request_id="req-001",
    actor="agent",
    intent="Do something",
    tool_call=ToolCall(name="tool", params={}),  # Add this
)

# Option 2: Disable requirement in policy
policy = JurisdictionPolicy(
    require_tool_call=False,  # Allow intent-only
    ...
)
```

#### Issue: Request denied - Intent too long

**Symptom:**
```json
{"decision": "DENY", "error": "Intent exceeds max length 1000"}
```

**Cause:** Intent exceeds `max_intent_length`.

**Solution:**
```python
# Shorten intent
request = Request(
    intent="Shorter intent...",  # Keep under limit
    ...
)

# Or increase limit
policy = JurisdictionPolicy(
    max_intent_length=5000,  # Increase limit
    ...
)
```

---

### 3.3 State Issues

#### Issue: Kernel is halted

**Symptom:**
```
StateError: Kernel is halted
```

**Cause:** Kernel was halted and cannot process requests.

**Solution:**
```python
# Create new kernel instance
kernel = StrictKernel(kernel_id="new-kernel", policy=policy)

# Note: Halted kernels cannot be restarted
# This is by design for safety
```

#### Issue: Kernel stuck in non-IDLE state

**Symptom:** Kernel state is not IDLE for extended period.

**Cause:** Long-running tool execution or error.

**Solution:**
```python
# Check current state
print(kernel.state)

# If stuck, halt and restart
kernel.halt()

# Create new kernel
kernel = StrictKernel(kernel_id="new-kernel", policy=policy)
```

---

### 3.4 Audit Issues

#### Issue: Audit chain verification failed

**Symptom:**
```python
is_valid, errors = replay_and_verify(entries, root_hash)
# is_valid = False
```

**Cause:** Audit entries were modified or corrupted.

**Solution:**
```python
# Check specific errors
for error in errors:
    print(error)

# Common causes:
# - Entry modified after creation
# - Entries out of order
# - Missing entries
# - Hash mismatch

# If corruption detected, investigate source
# Evidence may be compromised
```

#### Issue: Evidence export empty

**Symptom:**
```python
evidence = kernel.export_evidence()
print(len(evidence["ledger_entries"]))  # 0
```

**Cause:** No requests processed yet.

**Solution:**
```python
# Submit a request first
receipt = kernel.submit(request)

# Then export
evidence = kernel.export_evidence()
```

---

### 3.5 Server Issues

#### Issue: Connection refused

**Symptom:**
```
ConnectionRefusedError: [Errno 111] Connection refused
```

**Cause:** Server not running or wrong port.

**Solution:**
```bash
# Check if server is running
ps aux | grep kernels

# Check port
netstat -tlnp | grep 8080

# Start server
python -m shards_kernel.sdk.server
```

#### Issue: Address already in use

**Symptom:**
```
OSError: [Errno 98] Address already in use
```

**Cause:** Port already bound by another process.

**Solution:**
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use different port
python -c "
from shards_kernel.sdk import KernelServer, StrictKernel
server = KernelServer(StrictKernel('test'), port=8081)
server.start()
"
```

#### Issue: 503 Service Unavailable

**Symptom:**
```json
{"error": "No kernel"}
```

**Cause:** Server started without kernel.

**Solution:**
```python
# Ensure kernel is passed to server
from shards_kernel import StrictKernel
from shards_kernel.sdk import KernelServer

kernel = StrictKernel(kernel_id="server-kernel")
server = KernelServer(kernel, port=8080)
server.start()
```

---

### 3.6 Performance Issues

#### Issue: High latency

**Symptom:** Request processing > 100ms.

**Cause:** Slow tool execution or resource contention.

**Solution:**
```python
# Profile tool execution
import time

start = time.time()
receipt = kernel.submit(request)
print(f"Latency: {time.time() - start:.3f}s")

# Check tool execution time
# Optimize slow tools
# Consider async execution
```

#### Issue: Memory growing

**Symptom:** Memory usage increasing over time.

**Cause:** Audit ledger growing unbounded.

**Solution:**
```python
# Export and archive evidence periodically
evidence = kernel.export_evidence()
save_to_archive(evidence)

# Create new kernel with fresh ledger
kernel = StrictKernel(kernel_id="new-kernel", policy=policy)
```

---

## 4. Debugging Techniques

### 4.1 Enable Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("kernels")
logger.setLevel(logging.DEBUG)

# Now run your code - detailed logs will appear
```

### 4.2 Inspect Kernel State

```python
# Check state
print(f"State: {kernel.state}")
print(f"Kernel ID: {kernel.kernel_id}")

# Check policy
print(f"Allowed actors: {kernel.policy.allowed_actors}")
print(f"Allowed tools: {kernel.policy.allowed_tools}")

# Check audit
evidence = kernel.export_evidence()
print(f"Entries: {len(evidence['ledger_entries'])}")
print(f"Root hash: {evidence['root_hash']}")
```

### 4.3 Trace Request Processing

```python
from shards_kernel import StrictKernel, Request, ToolCall

# Create kernel with debug
kernel = StrictKernel(kernel_id="debug-kernel")

# Create request
request = Request(
    request_id="debug-001",
    actor="test-agent",
    intent="Debug test",
    tool_call=ToolCall(name="echo", params={"msg": "test"}),
)

# Submit and inspect
print(f"Before: {kernel.state}")
receipt = kernel.submit(request)
print(f"After: {kernel.state}")
print(f"Decision: {receipt.decision}")
print(f"Result: {receipt.result}")
print(f"Error: {receipt.error}")
```

### 4.4 Verify Audit Chain

```python
from shards_kernel.audit import replay_and_verify

evidence = kernel.export_evidence()
is_valid, errors = replay_and_verify(
    evidence["ledger_entries"],
    evidence["root_hash"]
)

print(f"Valid: {is_valid}")
if not is_valid:
    for error in errors:
        print(f"Error: {error}")
```

---

## 5. Error Reference

### 5.1 Exception Types

| Exception | Cause | Solution |
|-----------|-------|----------|
| `KernelError` | General kernel error | Check message |
| `ValidationError` | Invalid request | Fix request fields |
| `JurisdictionError` | Policy violation | Update policy |
| `StateError` | Invalid state transition | Check kernel state |
| `AuditError` | Audit failure | Check ledger |
| `ExecutionError` | Tool execution failed | Check tool |

### 5.2 Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `INVALID` | Request validation failed | Fix request |
| `DENIED` | Policy denied request | Update policy |
| `ERROR` | Execution error | Check tool |
| `HALTED` | Kernel halted | Create new kernel |

---

## 6. Recovery Procedures

### 6.1 Recover from Halt

```python
# Halted kernels cannot be recovered
# Export evidence first
evidence = old_kernel.export_evidence()
save_evidence(evidence)

# Create new kernel
new_kernel = StrictKernel(
    kernel_id=f"recovered-{int(time.time())}",
    policy=policy,
)
```

### 6.2 Recover from Corruption

```python
# If audit chain is corrupted
# 1. Preserve corrupted evidence
corrupted = kernel.export_evidence()
save_evidence(corrupted, "corrupted_evidence.json")

# 2. Create new kernel
new_kernel = StrictKernel(kernel_id="clean-kernel", policy=policy)

# 3. Investigate corruption source
# 4. Report incident
```

### 6.3 Recover from Crash

```bash
# Check for crash logs
journalctl -u kernels --since "1 hour ago"

# Restart service
sudo systemctl restart kernels

# Verify recovery
curl http://localhost:8080/health
```

---

## 7. Getting Help

### 7.1 Information to Collect

When reporting issues, include:

1. **Shards-Kernel version:** `python -c "import shards_kernel; print(shards_kernel.__version__)"`
2. **Python version:** `python --version`
3. **OS:** `uname -a`
4. **Error message:** Full traceback
5. **Minimal reproduction:** Code to reproduce issue
6. **Configuration:** Policy and kernel settings (sanitized)

### 7.2 Support Channels

| Channel | Use For |
|---------|---------|
| GitHub Issues | Bug reports |
| GitHub Discussions | Questions |
| Documentation | Reference |

---

## 8. Troubleshooting Checklist

### 8.1 Installation

- [ ] Python 3.11+ installed
- [ ] Package installed (`pip install -e .`)
- [ ] Import works (`import shards_kernel`)
- [ ] Version correct (`shards_kernel.__version__`)

### 8.2 Configuration

- [ ] Policy configured
- [ ] Actors listed
- [ ] Tools listed
- [ ] Limits set appropriately

### 8.3 Runtime

- [ ] Kernel state is IDLE
- [ ] Server is running
- [ ] Port is accessible
- [ ] Health check passes

### 8.4 Requests

- [ ] Request ID unique
- [ ] Actor in allowed list
- [ ] Tool in allowed list
- [ ] Intent within length limit
- [ ] Tool call present (if required)
