# OpenClaw Integration Guide

## Overview

[OpenClaw](https://openclaw.ai/) (formerly Clawdbot/Moltbook) is a viral open-source AI agent framework that achieved 60,000+ GitHub stars in 72 hours (January 2026). It provides autonomous AI assistance with broad system permissions.

**Security Concerns:**
> *"OpenClaw's design has drawn scrutiny from cybersecurity researchers due to the **broad permissions it requires to function effectively**, as the software can access email accounts, calendars, messaging platforms, and other sensitive services."*
>
> — CNBC, February 2026

**Shards-Kernel Solution:**
Cryptographic permit-based governance ensures OpenClaw AgentSkills can only execute dangerous operations with explicit authorization and complete audit trails.

---

## Integration Architecture

### OpenClaw AgentSkills

OpenClaw tools (called "AgentSkills") are JavaScript/TypeScript functions with JSON schemas:

```typescript
// OpenClaw skill definition (TypeScript)
export const shellExecute = {
  name: "shell_execute",
  description: "Execute shell command",
  parameters: {
    command: { type: "string", required: true }
  },
  execute: async (params: { command: string }) => {
    // Execute shell command
    return await executeCommand(params.command);
  }
};
```

### Shards-Kernel Governance Layer

Shards-Kernel wraps these skills with permit-based governance:

```python
# Shards-Kernel governed wrapper (Python)
from shards_kernel.integrations import GenericAdapter

adapter = GenericAdapter(kernel, actor="openclaw-assistant")

# Wrap OpenClaw skill
governed_shell = adapter.create_wrapper(
    name="shell_execute",
    func=shell_execute_fn,  # Python implementation
    description="Execute shell command (DANGEROUS)",
    raise_on_deny=True,
)

# Tool now requires permit
result = governed_shell(
    command="ls -la /home",
    permit_token=permit,  # Cryptographically signed
)
```

---

## Quick Start

### 1. Set Up Shards-Kernel Kernel

```python
from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.variants.strict_kernel import StrictKernel

# Initialize kernel
kernel = StrictKernel()
config = KernelConfig(
    kernel_id="openclaw-agent",
    variant="strict",
    clock=VirtualClock(),
)
kernel.boot(config)

# Configure cryptographic keyring
keyring = {"openclaw-operator-2026": b"secret-hmac-key-32-bytes-openclaw"}
kernel.set_keyring(keyring)
```

### 2. Create GenericAdapter

```python
from shards_kernel.integrations import GenericAdapter

adapter = GenericAdapter(
    kernel=kernel,
    actor="openclaw-assistant",
    auto_register=True,
)
```

### 3. Wrap OpenClaw AgentSkills

```python
# Example: Wrap dangerous tools

# Shell execution
governed_shell = adapter.create_wrapper(
    name="shell_execute",
    func=shell_execute_fn,
    description="Execute shell command",
    raise_on_deny=True,
)

# Email deletion
governed_email_delete = adapter.create_wrapper(
    name="email_delete",
    func=email_delete_fn,
    description="Delete emails",
    raise_on_deny=True,
)

# Calendar creation
governed_calendar = adapter.create_wrapper(
    name="calendar_create_event",
    func=calendar_create_fn,
    description="Create calendar event",
    raise_on_deny=True,
)

# Web actions
governed_web_action = adapter.create_wrapper(
    name="web_browse",
    func=web_browse_fn,
    description="Browse web with actions",
    raise_on_deny=True,
)

# Slack messaging
governed_slack = adapter.create_wrapper(
    name="slack_send_message",
    func=slack_send_fn,
    description="Send Slack message",
    raise_on_deny=True,
)
```

### 4. Create Permits for Authorized Operations

```python
from shards_kernel.permits import PermitBuilder

# Create permit for calendar event
calendar_permit = (
    PermitBuilder()
    .issuer("operator@company.com")
    .subject("openclaw-assistant")
    .jurisdiction("default")
    .action("calendar_create_event")
    .params({
        "title": "Team standup",
        "start_time": "2026-02-10 09:00",
        "attendees": "team@company.com",
    })
    .max_executions(1)
    .valid_from_ms(0)
    .valid_until_ms(10000000)
    .build(keyring, "openclaw-operator-2026")
)
```

### 5. Execute with Governance

```python
# WITHOUT permit: DENIED
try:
    result = governed_calendar(
        title="Team standup",
        start_time="2026-02-10 09:00",
        attendees="team@company.com",
    )
except Exception as e:
    print(f"Denied: {e}")  # "MISSING_PERMIT"

# WITH permit: ALLOWED
result = governed_calendar(
    title="Team standup",
    start_time="2026-02-10 09:00",
    attendees="team@company.com",
    permit_token=calendar_permit,
)
# Success! ✓
```

### 6. Export Audit Trail

```python
evidence = adapter.export_evidence()

# Evidence bundle contains:
# - Immutable hash-chained audit log
# - All tool executions (ALLOW/DENY)
# - Permit verification results
# - Replay protection status

import json
with open("openclaw_audit.json", "w") as f:
    json.dump(evidence, f, indent=2)
```

### 7. Verify Audit Trail

```bash
python -m shards_kernel.cli.verify openclaw_audit.json

# Output:
# ✓ Verification: PASSED
#   Checks passed: 5/5
#
# Statistics:
#   Decisions: {'ALLOW': 2, 'DENY': 2}
#   Permit Verification: {'verified': 2, 'denied': 2}
```

---

## Common OpenClaw AgentSkills to Govern

### High-Risk Tools (ALWAYS require permits)

| Skill | Risk | Why Governance Needed |
|-------|------|----------------------|
| `shell_execute` | CRITICAL | Arbitrary command execution |
| `email_delete` | HIGH | Permanent data loss |
| `email_send` | HIGH | Spam, phishing, reputational damage |
| `slack_send_message` (with @channel) | HIGH | Team spam, disruption |
| `calendar_create_event` | MEDIUM | Calendar spam, unwanted meetings |
| `web_browse` (submit/click) | MEDIUM | Unintended purchases, form submissions |
| `file_delete` | HIGH | Data loss |
| `database_query` (write) | CRITICAL | Data corruption |

### Moderate-Risk Tools (Consider permits)

| Skill | Risk | Governance Approach |
|-------|------|---------------------|
| `web_browse` (read) | LOW | Optional permit |
| `file_read` | LOW-MEDIUM | Permit for sensitive paths |
| `slack_send_message` (DM) | LOW | Optional permit |
| `calendar_read` | LOW | Usually safe |

### Safe Tools (No permit needed)

- `search_knowledge_base`
- `calculate`
- `format_text`
- `parse_json`

---

## Integration Patterns

### Pattern 1: Wrapper Function (Recommended)

```python
# Best for production use
governed_tool = adapter.create_wrapper(
    name="skill_name",
    func=skill_fn,
    description="Description",
    raise_on_deny=True,
)

result = governed_tool(**params, permit_token=permit)
```

### Pattern 2: Decorator Pattern

```python
# Best for new skill development
@adapter.govern("shell_execute", description="Execute shell command")
def shell_execute(command: str) -> str:
    return os.popen(command).read()

# Automatically requires permit
result = shell_execute(command="ls -la", permit_token=permit)
```

### Pattern 3: Direct Calling

```python
# Best for dynamic tool invocation
result = adapter.call_tool(
    tool_name="shell_execute",
    params={"command": "ls -la"},
    permit_token=permit,
)

# Returns ToolExecutionResult with detailed status
print(result.was_allowed)  # True/False
print(result.decision)      # ALLOW/DENY
print(result.error)         # Error message if denied
```

---

## Security Benefits

### What Shards-Kernel Prevents in OpenClaw

| Attack Vector | Without Shards-Kernel | With Shards-Kernel |
|---------------|----------------|--------------|
| **Prompt Injection** | Agent executes `rm -rf /` from malicious prompt | DENIED: MISSING_PERMIT |
| **Data Exfiltration** | Agent emails sensitive files to attacker | DENIED: Permit required for email |
| **Credential Theft** | Agent accesses `.aws/credentials` | DENIED: File access governed |
| **Resource Abuse** | Agent spawns infinite processes | DENIED: Shell execution governed |
| **Social Engineering** | Agent sends phishing emails from user's account | DENIED: Permit validates exact content |
| **Replay Attacks** | Attacker reuses intercepted permit | DENIED: Nonce exhausted |

### Compliance Alignment

OpenClaw + Shards-Kernel addresses regulatory requirements:

- **EU AI Act (Art. 12)**: Record-keeping through immutable audit chain
- **EU AI Act (Art. 14)**: Human oversight through permit authorization
- **ISO 42001**: AI management system controls
- **SOC 2**: Security, availability, and confidentiality controls
- **NIST AI RMF**: Risk management and governance

See [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for detailed mappings.

---

## Production Deployment

### 1. Permit Issuance Workflow

```python
# Operator reviews agent's request
request = {
    "action": "email_delete",
    "params": {
        "mailbox": "inbox",
        "filter_query": "from:spam@example.com",
    },
    "justification": "User requested spam cleanup",
}

# Operator approves and issues permit
permit = (
    PermitBuilder()
    .issuer("operator@company.com")
    .subject("openclaw-assistant")
    .action(request["action"])
    .params(request["params"])
    .proposal_hash(request["justification"])
    .max_executions(1)
    .build(keyring, "operator-key")
)

# Agent executes with permit
result = governed_email_delete(**request["params"], permit_token=permit)
```

### 2. Audit Trail Monitoring

```python
# Periodic audit trail export
evidence = adapter.export_evidence()

# Check for suspicious patterns
for entry in evidence["entries"]:
    if entry["decision"] == "DENY":
        alert_security_team(entry)

    if entry.get("permit_denial_reasons") and "REPLAY_DETECTED" in entry["permit_denial_reasons"]:
        alert_security_team("Replay attack detected!")
```

### 3. Verification in CI/CD

```bash
# Automated verification in CI
python -m shards_kernel.cli.verify audit_trail.json || exit 1

# Expected output:
# ✓ Hash Chain: PASSED
# ✓ Sequence Numbering: PASSED
# ✓ Permit Enforcement: PASSED
# ✓ Replay Protection: PASSED
# ✓ State Transitions: PASSED
```

---

## Example: Complete Integration

See `examples/08_openclaw_governed_agent.py` for a complete working example that demonstrates:

1. Kernel initialization with keyring
2. Wrapping 5 dangerous OpenClaw AgentSkills
3. Denial of unauthorized operations
4. Permit creation and signing
5. Authorized execution with permits
6. Audit trail export and verification

**Run the example:**

```bash
python examples/08_openclaw_governed_agent.py

# Output shows:
# ✓ Shell execution denied without permit
# ✓ Email deletion denied without permit
# ✓ Calendar creation allowed with permit
# ✓ Web action allowed with permit
# ✓ Complete audit trail exported
```

---

## TypeScript/JavaScript Integration

While this guide focuses on Python, OpenClaw is primarily TypeScript/JavaScript. For native integration:

### Option 1: Python Backend with TS Frontend

- OpenClaw (TypeScript) → HTTP API → Shards-Kernel (Python)
- Use FastAPI adapter: `create_fastapi_app(kernel)`
- OpenClaw skills call governed HTTP endpoints

### Option 2: TypeScript Port (Future)

- TypeScript implementation of Shards-Kernel protocol
- Native integration with OpenClaw skills
- See roadmap in main README

### Option 3: Protocol Bridge

- Implement Shards-Kernel permit protocol in TypeScript
- Python kernel validates permits over gRPC/HTTP
- Shared cryptographic keyring

---

## Frequently Asked Questions

### Q: Does this slow down OpenClaw?

**A:** Minimal overhead (~1-5ms per tool call for permit verification). The security benefits far outweigh the negligible latency.

### Q: Can I use Shards-Kernel with existing OpenClaw deployments?

**A:** Yes! Wrap existing skills progressively. Start with high-risk tools (shell, email, file operations) and expand coverage.

### Q: What if OpenClaw updates its skill API?

**A:** GenericAdapter is framework-agnostic. Update your Python wrapper functions to match OpenClaw's new API, governance layer remains unchanged.

### Q: How do I generate permits programmatically?

**A:** Use `PermitBuilder` with your approval workflow:

```python
# Example: Approval bot
if user_approves_action(action, params):
    permit = PermitBuilder().action(action).params(params).build(keyring, key_id)
    execute_with_permit(action, params, permit)
```

### Q: Can I audit historical OpenClaw actions?

**A:** Yes! Export evidence bundle and use verification CLI:

```bash
python -m shards_kernel.cli.verify historical_audit.json --detailed
```

Shows all tool executions with timestamps, decisions, and permit status.

---

## Resources

- **Example Code**: `examples/08_openclaw_governed_agent.py`
- **Compliance Mapping**: `docs/COMPLIANCE_MAPPING.md`
- **Verification CLI**: `shards_kernel/cli/verify.py`
- **OpenClaw Project**: https://openclaw.ai/
- **Shards-Kernel Repository**: https://github.com/Shards-foundation/Shards-kernel

---

## Summary

Shards-Kernel transforms OpenClaw from a powerful-but-risky autonomous agent into a **governed, auditable, and compliant** AI assistant:

✓ **Fail-closed**: Dangerous operations denied by default
✓ **Cryptographic**: HMAC-SHA256 signed permits
✓ **Auditable**: Immutable hash-chained audit trail
✓ **Verifiable**: Independent CLI verification
✓ **Compliant**: Meets EU AI Act, ISO 42001, SOC 2 requirements
✓ **Adoptable**: Drop-in wrapper for existing OpenClaw skills

**The future of autonomous agents is governed, not rogue.**
