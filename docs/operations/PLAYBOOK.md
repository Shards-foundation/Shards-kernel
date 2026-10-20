# KERNELS Operations Playbook

**Version:** 0.1.0  
**Classification:** Operations  
**Last Updated:** January 2025

---

## 1. Overview

This playbook provides step-by-step procedures for operating KERNELS in production environments. Follow these plays to handle common operational scenarios.

---

## 2. Startup Plays

### Play 2.1: Initial Deployment

**Trigger:** First-time deployment of KERNELS

**Steps:**

```bash
# Step 1: Clone repository
git clone https://github.com/Shards-foundation/kernels.git
cd kernels

# Step 2: Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Step 3: Install package
pip install -e .

# Step 4: Verify installation
python -m kernels info

# Step 5: Run smoke test
./scripts/smoke.sh

# Step 6: Configure policy
cat > config/policy.yaml << EOF
allowed_actors:
  - agent-001
  - agent-002
allowed_tools:
  - read_file
  - write_file
  - search
require_tool_call: true
max_intent_length: 1000
EOF

# Step 7: Start kernel
python -c "
from kernels import StrictKernel, JurisdictionPolicy
import yaml

with open('config/policy.yaml') as f:
    config = yaml.safe_load(f)

policy = JurisdictionPolicy(**config)
kernel = StrictKernel(kernel_id='prod-001', policy=policy)
print(f'Kernel {kernel.kernel_id} started in state {kernel.state}')
"
```

**Verification:**
- [ ] `python -m kernels info` shows version
- [ ] Smoke test passes
- [ ] Kernel state is IDLE

---

### Play 2.2: Service Restart

**Trigger:** Kernel service needs restart

**Steps:**

```bash
# Step 1: Export current evidence (if possible)
python -c "
from kernels import StrictKernel
kernel = get_running_kernel()  # Your method to get kernel
evidence = kernel.export_evidence()
save_evidence(evidence, 'backup/evidence_$(date +%Y%m%d_%H%M%S).json')
"

# Step 2: Stop service gracefully
systemctl stop kernels

# Step 3: Verify stopped
systemctl status kernels

# Step 4: Start service
systemctl start kernels

# Step 5: Verify running
systemctl status kernels

# Step 6: Health check
curl http://localhost:8080/health
```

**Verification:**
- [ ] Service status is active
- [ ] Health check returns 200
- [ ] Kernel state is IDLE

---

## 3. Monitoring Plays

### Play 3.1: Daily Health Check

**Trigger:** Daily scheduled check

**Steps:**

```python
# daily_health_check.py
from kernels import StrictKernel
from kernels.audit import replay_and_verify

def daily_health_check(kernel):
    checks = []
    
    # Check 1: Kernel state
    checks.append({
        "name": "kernel_state",
        "passed": kernel.state.value in ["IDLE", "HALTED"],
        "value": kernel.state.value
    })
    
    # Check 2: Audit chain integrity
    evidence = kernel.export_evidence()
    is_valid, errors = replay_and_verify(
        evidence["ledger_entries"],
        evidence["root_hash"]
    )
    checks.append({
        "name": "audit_integrity",
        "passed": is_valid,
        "errors": errors
    })
    
    # Check 3: Decision distribution
    entries = evidence["ledger_entries"]
    allow_count = sum(1 for e in entries if e.get("decision") == "ALLOW")
    deny_count = sum(1 for e in entries if e.get("decision") == "DENY")
    checks.append({
        "name": "decision_distribution",
        "passed": True,
        "allow": allow_count,
        "deny": deny_count,
        "ratio": allow_count / max(deny_count, 1)
    })
    
    # Check 4: Recent activity
    if entries:
        last_entry = entries[-1]
        last_ts = last_entry.get("ts_ms", 0)
        age_hours = (time.time() * 1000 - last_ts) / 3600000
        checks.append({
            "name": "recent_activity",
            "passed": age_hours < 24,
            "last_activity_hours": age_hours
        })
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "kernel_id": kernel.kernel_id,
        "all_passed": all(c["passed"] for c in checks),
        "checks": checks
    }
```

**Verification:**
- [ ] All checks pass
- [ ] Audit chain is valid
- [ ] Recent activity within 24 hours

---

### Play 3.2: Anomaly Investigation

**Trigger:** Unusual pattern detected in metrics

**Steps:**

```python
# investigate_anomaly.py
from kernels import StrictKernel

def investigate_anomaly(kernel, start_ts, end_ts):
    evidence = kernel.export_evidence()
    entries = evidence["ledger_entries"]
    
    # Filter to time range
    relevant = [
        e for e in entries
        if start_ts <= e.get("ts_ms", 0) <= end_ts
    ]
    
    # Analyze patterns
    analysis = {
        "time_range": {"start": start_ts, "end": end_ts},
        "entry_count": len(relevant),
        "by_actor": {},
        "by_tool": {},
        "by_decision": {},
        "errors": []
    }
    
    for entry in relevant:
        # Count by actor
        actor = entry.get("actor", "unknown")
        analysis["by_actor"][actor] = analysis["by_actor"].get(actor, 0) + 1
        
        # Count by tool
        tool = entry.get("tool_name", "none")
        analysis["by_tool"][tool] = analysis["by_tool"].get(tool, 0) + 1
        
        # Count by decision
        decision = entry.get("decision", "unknown")
        analysis["by_decision"][decision] = analysis["by_decision"].get(decision, 0) + 1
        
        # Collect errors
        if entry.get("error"):
            analysis["errors"].append({
                "request_id": entry.get("request_id"),
                "error": entry.get("error"),
                "ts_ms": entry.get("ts_ms")
            })
    
    return analysis
```

**Verification:**
- [ ] Anomaly source identified
- [ ] Root cause documented
- [ ] Remediation plan created

---

## 4. Incident Response Plays

### Play 4.1: Emergency Halt

**Trigger:** Security incident or runaway behavior detected

**Steps:**

```python
# emergency_halt.py
import time
from kernels import StrictKernel

def emergency_halt(kernel, reason):
    # Step 1: Record pre-halt state
    pre_halt = {
        "kernel_id": kernel.kernel_id,
        "state": kernel.state.value,
        "timestamp": time.time(),
        "reason": reason
    }
    
    # Step 2: Export evidence before halt
    try:
        evidence = kernel.export_evidence()
        save_evidence(evidence, f"incident/pre_halt_{int(time.time())}.json")
    except Exception as e:
        pre_halt["evidence_export_error"] = str(e)
    
    # Step 3: Issue halt
    kernel.halt()
    
    # Step 4: Verify halt
    assert kernel.state.value == "HALTED", "Halt failed!"
    
    # Step 5: Log incident
    log_incident({
        "type": "EMERGENCY_HALT",
        "pre_halt": pre_halt,
        "post_state": kernel.state.value,
        "timestamp": time.time()
    })
    
    # Step 6: Alert on-call
    send_alert(
        severity="CRITICAL",
        message=f"Kernel {kernel.kernel_id} halted: {reason}"
    )
    
    return pre_halt
```

**Verification:**
- [ ] Kernel state is HALTED
- [ ] Evidence exported
- [ ] Incident logged
- [ ] On-call alerted

---

### Play 4.2: Evidence Preservation

**Trigger:** Incident requires evidence preservation

**Steps:**

```python
# preserve_evidence.py
import hashlib
import json
from datetime import datetime

def preserve_evidence(kernel, incident_id):
    # Step 1: Export evidence
    evidence = kernel.export_evidence()
    
    # Step 2: Add preservation metadata
    preserved = {
        "incident_id": incident_id,
        "preserved_at": datetime.utcnow().isoformat(),
        "kernel_id": kernel.kernel_id,
        "evidence": evidence
    }
    
    # Step 3: Compute integrity hash
    content = json.dumps(preserved, sort_keys=True)
    preserved["integrity_hash"] = hashlib.sha256(content.encode()).hexdigest()
    
    # Step 4: Save to immutable storage
    filename = f"preserved/{incident_id}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(preserved, f, indent=2)
    
    # Step 5: Verify save
    with open(filename, 'r') as f:
        loaded = json.load(f)
    
    assert loaded["integrity_hash"] == preserved["integrity_hash"]
    
    # Step 6: Log preservation
    log_event({
        "type": "EVIDENCE_PRESERVED",
        "incident_id": incident_id,
        "filename": filename,
        "entry_count": len(evidence["ledger_entries"]),
        "root_hash": evidence["root_hash"]
    })
    
    return filename
```

**Verification:**
- [ ] Evidence file created
- [ ] Integrity hash matches
- [ ] Preservation logged

---

### Play 4.3: Post-Incident Recovery

**Trigger:** After incident resolution, restore service

**Steps:**

```python
# post_incident_recovery.py
from kernels import StrictKernel, JurisdictionPolicy

def post_incident_recovery(incident_id, policy_updates=None):
    # Step 1: Review incident
    incident = load_incident(incident_id)
    assert incident["status"] == "RESOLVED", "Incident not resolved"
    
    # Step 2: Apply policy updates if any
    policy_config = load_policy_config()
    if policy_updates:
        policy_config.update(policy_updates)
        save_policy_config(policy_config)
    
    # Step 3: Create new kernel instance
    policy = JurisdictionPolicy(**policy_config)
    kernel = StrictKernel(
        kernel_id=f"prod-{int(time.time())}",
        policy=policy
    )
    
    # Step 4: Verify kernel state
    assert kernel.state.value == "IDLE"
    
    # Step 5: Run smoke test
    from tests.smoke import run_smoke_test
    result = run_smoke_test(kernel)
    assert result["passed"], f"Smoke test failed: {result}"
    
    # Step 6: Enable traffic
    enable_traffic(kernel)
    
    # Step 7: Monitor closely
    schedule_enhanced_monitoring(kernel, duration_hours=24)
    
    return kernel
```

**Verification:**
- [ ] Incident marked resolved
- [ ] New kernel started
- [ ] Smoke test passed
- [ ] Traffic enabled
- [ ] Enhanced monitoring active

---

## 5. Maintenance Plays

### Play 5.1: Policy Update

**Trigger:** Need to update jurisdiction policy

**Steps:**

```python
# update_policy.py
from kernels import StrictKernel, JurisdictionPolicy

def update_policy(kernel, new_policy_config):
    # Step 1: Validate new policy
    try:
        new_policy = JurisdictionPolicy(**new_policy_config)
    except Exception as e:
        raise ValueError(f"Invalid policy: {e}")
    
    # Step 2: Export current evidence
    evidence = kernel.export_evidence()
    save_evidence(evidence, f"backup/pre_policy_update_{int(time.time())}.json")
    
    # Step 3: Log policy change
    log_event({
        "type": "POLICY_UPDATE",
        "old_policy": serialize_policy(kernel.policy),
        "new_policy": new_policy_config,
        "timestamp": time.time()
    })
    
    # Step 4: Create new kernel with new policy
    new_kernel = StrictKernel(
        kernel_id=kernel.kernel_id,
        policy=new_policy
    )
    
    # Step 5: Verify new kernel
    assert new_kernel.state.value == "IDLE"
    
    # Step 6: Switch traffic
    switch_traffic(kernel, new_kernel)
    
    return new_kernel
```

**Verification:**
- [ ] New policy validated
- [ ] Evidence backed up
- [ ] Change logged
- [ ] New kernel running
- [ ] Traffic switched

---

### Play 5.2: Evidence Export and Rotation

**Trigger:** Scheduled evidence rotation (weekly)

**Steps:**

```python
# rotate_evidence.py
from kernels import StrictKernel

def rotate_evidence(kernel):
    # Step 1: Export current evidence
    evidence = kernel.export_evidence()
    
    # Step 2: Save to archive
    filename = f"archive/evidence_{kernel.kernel_id}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(evidence, f)
    
    # Step 3: Verify archive
    from kernels.audit import replay_and_verify
    with open(filename, 'r') as f:
        archived = json.load(f)
    
    is_valid, errors = replay_and_verify(
        archived["ledger_entries"],
        archived["root_hash"]
    )
    assert is_valid, f"Archive verification failed: {errors}"
    
    # Step 4: Upload to long-term storage
    upload_to_s3(filename, f"kernels-archive/{kernel.kernel_id}/")
    
    # Step 5: Log rotation
    log_event({
        "type": "EVIDENCE_ROTATED",
        "kernel_id": kernel.kernel_id,
        "entry_count": len(evidence["ledger_entries"]),
        "root_hash": evidence["root_hash"],
        "archive_path": filename
    })
    
    return filename
```

**Verification:**
- [ ] Evidence exported
- [ ] Archive verified
- [ ] Uploaded to S3
- [ ] Rotation logged

---

## 6. Scaling Plays

### Play 6.1: Add Kernel Instance

**Trigger:** Need additional capacity

**Steps:**

```python
# add_kernel_instance.py
from kernels import StrictKernel, JurisdictionPolicy

def add_kernel_instance(cluster_id, instance_number):
    # Step 1: Load shared policy
    policy_config = load_cluster_policy(cluster_id)
    policy = JurisdictionPolicy(**policy_config)
    
    # Step 2: Create new kernel
    kernel_id = f"{cluster_id}-{instance_number:03d}"
    kernel = StrictKernel(kernel_id=kernel_id, policy=policy)
    
    # Step 3: Verify kernel
    assert kernel.state.value == "IDLE"
    
    # Step 4: Register with load balancer
    register_with_lb(kernel_id, get_instance_address())
    
    # Step 5: Enable health checks
    enable_health_checks(kernel_id)
    
    # Step 6: Log addition
    log_event({
        "type": "KERNEL_ADDED",
        "cluster_id": cluster_id,
        "kernel_id": kernel_id,
        "timestamp": time.time()
    })
    
    return kernel
```

**Verification:**
- [ ] Kernel created
- [ ] Registered with LB
- [ ] Health checks passing
- [ ] Addition logged

---

## 7. Runbook Quick Reference

| Scenario | Play | Priority |
|----------|------|----------|
| First deployment | 2.1 | P1 |
| Service restart | 2.2 | P1 |
| Daily health check | 3.1 | P2 |
| Anomaly detected | 3.2 | P1 |
| Security incident | 4.1 | P0 |
| Evidence preservation | 4.2 | P0 |
| Post-incident recovery | 4.3 | P1 |
| Policy update | 5.1 | P2 |
| Evidence rotation | 5.2 | P3 |
| Scale out | 6.1 | P2 |

---

## 8. Contact Information

| Role | Contact |
|------|---------|
| On-call | oncall@example.com |
| Security | security@example.com |
| Architecture | architecture@example.com |
