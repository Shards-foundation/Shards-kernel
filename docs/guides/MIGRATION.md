# Shards-Kernel Migration Guide

**Version:** 0.1.0  
**Classification:** Guide  
**Last Updated:** January 2025

---

## 1. Overview

This guide covers migration scenarios for Shards-Kernel deployments.

---

## 2. Version Migration

### 2.1 Migrating from 0.1.x to 0.2.x

*(Future release - placeholder)*

**Breaking Changes:**
- None planned

**Migration Steps:**

For the Python import namespace change, consult [PACKAGE_MIGRATION.md](../PACKAGE_MIGRATION.md).
1. Update package: `pip install --upgrade shards-kernel` (after an approved release)
2. Review changelog for new features
3. Test in staging environment
4. Deploy to production

---

## 3. Kernel Replacement

### 3.1 Why Replace Shards-Kernel

Shards-Kernel are designed to be **replaced, not restarted**. Replace when:

- Kernel has halted
- Policy needs updating
- Evidence needs archival
- Version upgrade required
- Configuration change needed

### 3.2 Replacement Procedure

```python
from shards_kernel import StrictKernel, JurisdictionPolicy
import time
import json

def replace_kernel(old_kernel, new_policy):
    """
    Replace a kernel with a new instance.
    
    Args:
        old_kernel: The kernel to replace
        new_policy: Policy for new kernel
        
    Returns:
        New kernel instance
    """
    # Step 1: Export evidence from old kernel
    evidence = old_kernel.export_evidence()
    
    # Step 2: Archive evidence
    archive_path = f"evidence/archive_{int(time.time())}.json"
    with open(archive_path, "w") as f:
        json.dump(evidence, f)
    print(f"Evidence archived to {archive_path}")
    
    # Step 3: Verify evidence integrity
    from shards_kernel.audit import replay_and_verify
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    if not is_valid:
        raise ValueError(f"Evidence verification failed: {errors}")
    
    # Step 4: Create new kernel
    new_kernel = StrictKernel(
        kernel_id=f"kernel-{int(time.time())}",
        policy=new_policy,
    )
    
    print(f"New kernel created: {new_kernel.kernel_id}")
    return new_kernel

# Usage
old_kernel = current_kernel
new_policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],
    allowed_tools=["read_file", "write_file"],
)

new_kernel = replace_kernel(old_kernel, new_policy)
```

### 3.3 Zero-Downtime Replacement

```python
import threading

class KernelManager:
    """Manages kernel lifecycle with zero-downtime replacement."""
    
    def __init__(self, initial_kernel):
        self._kernel = initial_kernel
        self._lock = threading.Lock()
    
    @property
    def kernel(self):
        with self._lock:
            return self._kernel
    
    def replace(self, new_kernel):
        """Replace kernel atomically."""
        with self._lock:
            old_kernel = self._kernel
            self._kernel = new_kernel
        
        # Archive old kernel evidence asynchronously
        threading.Thread(
            target=self._archive_evidence,
            args=(old_kernel,)
        ).start()
    
    def _archive_evidence(self, kernel):
        evidence = kernel.export_evidence()
        # Archive to storage...

# Usage
manager = KernelManager(initial_kernel)

# Submit requests through manager
receipt = manager.kernel.submit(request)

# Replace kernel without downtime
manager.replace(new_kernel)
```

---

## 4. Policy Migration

### 4.1 Adding New Actors

```python
# Current policy
old_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
)

# New policy with additional actor
new_policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002"],  # Added agent-002
    allowed_tools=["read_file"],
)

# Replace kernel with new policy
new_kernel = StrictKernel(kernel_id="updated", policy=new_policy)
```

### 4.2 Adding New Tools

```python
# Current policy
old_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
)

# New policy with additional tool
new_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file", "write_file"],  # Added write_file
)

# Also register the new tool
registry.register("write_file", write_file_fn)

# Replace kernel
new_kernel = StrictKernel(
    kernel_id="updated",
    policy=new_policy,
    tool_registry=registry,
)
```

### 4.3 Removing Permissions

```python
# Current policy (too permissive)
old_policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002", "agent-003"],
    allowed_tools=["read_file", "write_file", "delete_file"],
)

# New policy (restricted)
new_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],  # Removed agent-002, agent-003
    allowed_tools=["read_file"],   # Removed write_file, delete_file
)

# Replace kernel
new_kernel = StrictKernel(kernel_id="restricted", policy=new_policy)
```

### 4.4 Adding Custom Rules

```python
from shards_kernel.jurisdiction import RuleResult

# New custom rule
def require_business_hours(request):
    from datetime import datetime
    hour = datetime.utcnow().hour
    if 9 <= hour < 17:
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Outside business hours")

# New policy with custom rule
new_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
    custom_rules=[require_business_hours],  # Added rule
)

# Replace kernel
new_kernel = StrictKernel(kernel_id="with-rules", policy=new_policy)
```

---

## 5. Variant Migration

### 5.1 Strict to Permissive

For development/testing:

```python
from shards_kernel import StrictKernel, PermissiveKernel

# Production: Strict
prod_kernel = StrictKernel(
    kernel_id="prod",
    policy=strict_policy,
)

# Development: Permissive
dev_kernel = PermissiveKernel(
    kernel_id="dev",
    # Uses permissive defaults
)
```

### 5.2 Permissive to Strict

For production hardening:

```python
# Development: Permissive
dev_kernel = PermissiveKernel(kernel_id="dev")

# Production: Strict with explicit policy
prod_policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
    require_tool_call=True,
    max_intent_length=500,
)

prod_kernel = StrictKernel(
    kernel_id="prod",
    policy=prod_policy,
)
```

### 5.3 To Evidence-First

For audit-heavy environments:

```python
from shards_kernel import EvidenceFirstKernel

# Migrate to evidence-first
kernel = EvidenceFirstKernel(
    kernel_id="audit-kernel",
    policy=policy,
)

# Requests now require evidence
request = Request(
    request_id="req-001",
    actor="agent",
    intent="Action",
    tool_call=tool_call,
    evidence=["evidence-001"],  # Required
)
```

### 5.4 To Dual-Channel

For structured workflows:

```python
from shards_kernel import DualChannelKernel

# Migrate to dual-channel
kernel = DualChannelKernel(
    kernel_id="workflow-kernel",
    policy=policy,
)

# Requests now require constraints
request = Request(
    request_id="req-001",
    actor="agent",
    intent="Summarize document",
    tool_call=tool_call,
    constraints={  # Required
        "scope": "Executive summary",
        "non_goals": ["No financials"],
        "success_criteria": ["Under 200 words"],
    },
)
```

---

## 6. Evidence Migration

### 6.1 Export Evidence

```python
def export_all_evidence(kernel, output_path):
    """Export all evidence to file."""
    evidence = kernel.export_evidence()
    
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)
    
    print(f"Exported {evidence['entry_count']} entries to {output_path}")
    return evidence
```

### 6.2 Archive Evidence

```python
import gzip
import json
from datetime import datetime

def archive_evidence(evidence, archive_dir="evidence/archive"):
    """Archive evidence with compression."""
    os.makedirs(archive_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().isoformat()
    filename = f"{evidence['kernel_id']}_{timestamp}.json.gz"
    filepath = os.path.join(archive_dir, filename)
    
    with gzip.open(filepath, "wt") as f:
        json.dump(evidence, f)
    
    print(f"Archived to {filepath}")
    return filepath
```

### 6.3 Verify Archived Evidence

```python
import gzip
from shards_kernel.audit import replay_and_verify

def verify_archived_evidence(archive_path):
    """Verify archived evidence integrity."""
    with gzip.open(archive_path, "rt") as f:
        evidence = json.load(f)
    
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    
    if is_valid:
        print(f"✓ Archive verified: {archive_path}")
    else:
        print(f"✗ Archive verification failed: {archive_path}")
        for error in errors:
            print(f"  - {error}")
    
    return is_valid
```

---

## 7. Server Migration

### 7.1 Migrate to FastAPI

```python
# Before: Built-in server
from shards_kernel.sdk import KernelServer

server = KernelServer(kernel, port=8080)
server.start()

# After: FastAPI
from shards_kernel.integrations import create_fastapi_app
import uvicorn

app = create_fastapi_app(kernel)
uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 7.2 Migrate to Flask

```python
# Before: Built-in server
from shards_kernel.sdk import KernelServer

server = KernelServer(kernel, port=8080)
server.start()

# After: Flask
from shards_kernel.integrations import create_flask_app

app = create_flask_app(kernel)
app.run(host="0.0.0.0", port=8080)
```

### 7.3 Add Load Balancer

```nginx
# nginx.conf
upstream kernels {
    server kernel1:8080;
    server kernel2:8080;
    server kernel3:8080;
}

server {
    listen 80;
    
    location / {
        proxy_pass http://kernels;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /health {
        proxy_pass http://shards_kernel/health;
    }
}
```

---

## 8. Client Migration

### 8.1 Migrate to SDK Client

```python
# Before: Direct HTTP
import requests

response = requests.post(
    "http://localhost:8080/submit",
    json={
        "request_id": "req-001",
        "actor": "agent",
        "intent": "Do something",
        "tool_call": {"name": "tool", "params": {}},
    }
)
result = response.json()

# After: SDK Client
from shards_kernel.sdk import KernelClient
from shards_kernel import Request, ToolCall

client = KernelClient("http://localhost:8080")

request = Request(
    request_id="req-001",
    actor="agent",
    intent="Do something",
    tool_call=ToolCall(name="tool", params={}),
)

receipt = client.submit(request)
```

### 8.2 Migrate to Async Client

```python
# Before: Sync client
from shards_kernel.sdk import KernelClient

client = KernelClient("http://localhost:8080")
receipt = client.submit(request)

# After: Async client
from shards_kernel.sdk import AsyncKernelClient

client = AsyncKernelClient("http://localhost:8080")
receipt = await client.submit(request)
```

---

## 9. Migration Checklist

### 9.1 Pre-Migration

- [ ] Document current configuration
- [ ] Export all evidence
- [ ] Verify evidence integrity
- [ ] Plan rollback procedure
- [ ] Notify stakeholders
- [ ] Schedule maintenance window

### 9.2 During Migration

- [ ] Stop accepting new requests
- [ ] Wait for in-flight requests
- [ ] Export final evidence
- [ ] Verify final evidence
- [ ] Deploy new configuration
- [ ] Start new kernel
- [ ] Verify health check
- [ ] Resume accepting requests

### 9.3 Post-Migration

- [ ] Verify functionality
- [ ] Monitor for errors
- [ ] Archive old evidence
- [ ] Update documentation
- [ ] Notify stakeholders
- [ ] Close maintenance window

---

## 10. Rollback Procedures

### 10.1 Quick Rollback

```python
def rollback(current_kernel, previous_policy, previous_registry):
    """Rollback to previous configuration."""
    # Export current evidence
    evidence = current_kernel.export_evidence()
    archive_evidence(evidence, "rollback")
    
    # Create kernel with previous config
    rollback_kernel = StrictKernel(
        kernel_id=f"rollback-{int(time.time())}",
        policy=previous_policy,
        tool_registry=previous_registry,
    )
    
    return rollback_kernel
```

### 10.2 Full Rollback

```bash
#!/bin/bash
# rollback.sh

# Stop current service
sudo systemctl stop kernels

# Restore previous configuration
cp /etc/shards_kernel/backup/shards_kernel.yaml /etc/shards_kernel/shards_kernel.yaml

# Start service
sudo systemctl start kernels

# Verify health
curl http://localhost:8080/health
```
