# Agent Framework Integrations

## Overview

Shards-Kernel provides first-class integrations with the leading AI agent frameworks, enabling permit-based governance for autonomous AI systems. This document covers integrations with **CrewAI**, **AutoGPT**, and **LangGraph** - three fundamentally different agent paradigms.

**Why Agent Governance Matters:**
- Agents can execute arbitrary code, shell commands, and API calls
- Multi-agent systems can escalate privileges through delegation chains
- Stateful workflows can violate business logic constraints
- Autonomous loops can consume unlimited resources
- No built-in authorization or audit trails in most frameworks

**Shards-Kernel Solution:**
- Cryptographic permit-based authorization
- Multi-agent delegation control
- State transition validation
- Autonomous loop monitoring with kill-switch
- Complete immutable audit trails
- Framework-agnostic governance layer

---

## Framework Coverage

| Framework | Type | Integration | Example | Status |
|-----------|------|-------------|---------|--------|
| **LangChain** | Agent tools | `LangChainAdapter` | `06_langchain_governed_agent.py` | ✅ Complete |
| **LangGraph** | Stateful workflows | `LangGraphAdapter` | `11_langgraph_stateful_governance.py` | ✅ Complete |
| **CrewAI** | Multi-agent orchestration | `CrewAIAdapter` | `09_crewai_multiagent_governance.py` | ✅ Complete |
| **AutoGPT** | Autonomous agents | `AutoGPTAdapter` | `10_autogpt_autonomous_governance.py` | ✅ Complete |
| **Hugging Face** | Model hub + tools | `HuggingFaceAdapter` | `07_huggingface_governed_agent.py` | ✅ Complete |
| **OpenClaw** | Personal AI assistant | `GenericAdapter` | `08_openclaw_governed_agent.py` | ✅ Complete |

---

## Integration 1: CrewAI (Multi-Agent Orchestration)

### Overview

[CrewAI](https://www.crewai.com/) is a multi-agent orchestration framework that enables agents to collaborate through delegation and context sharing. It went viral in 2024-2025 as the leading framework for building agent crews.

**Governance Challenges:**
- **Agent-to-agent delegation** can bypass security controls
- **Privilege escalation** through delegation chains
- **Role confusion** when agents exceed their intended scope
- **No audit trail** of inter-agent interactions

### Architecture

```
┌─────────────┐
│ Researcher  │ (LOW RISK: web search, file read)
└──────┬──────┘
       │ delegates to
       ▼
┌─────────────┐
│  Analyst    │ (MEDIUM RISK: data analysis, reports)
└──────┬──────┘
       │ delegates to
       ▼
┌─────────────┐
│  Publisher  │ (HIGH RISK: file write, email, publish)
└─────────────┘

Shards-Kernel Policy Layer:
├── Tool governance per agent role
├── Delegation matrix validation
├── Agent identity attestation
└── Complete audit trail
```

### Quick Start

```python
from shards_kernel.integrations import CrewAIAdapter
from shards_kernel.variants.strict_kernel import StrictKernel

# Initialize kernel
kernel = StrictKernel()
kernel.boot(...)
keyring = {"crew-operator": b"secret-key"}
kernel.set_keyring(keyring)

# Create adapter
adapter = CrewAIAdapter(kernel, actor="crew-orchestrator")

# Create agent identities
researcher_id = adapter.create_agent_identity("Researcher")
publisher_id = adapter.create_agent_identity("Publisher")

# Wrap tools with agent-specific governance
search_tool = adapter.wrap_tool(
    name="web_search",
    func=web_search_fn,
    actor=researcher_id,
    require_permit=False,  # LOW RISK
)

email_tool = adapter.wrap_tool(
    name="send_email",
    func=send_email_fn,
    actor=publisher_id,
    require_permit=True,  # HIGH RISK
)

# Define delegation matrix (prevent privilege escalation)
delegation_matrix = {
    researcher_id: [analyst_id],  # Can only delegate to Analyst
    analyst_id: [publisher_id],   # Can only delegate to Publisher
    publisher_id: [],              # Cannot delegate further
}

# Validate delegation
can_delegate = adapter.validate_delegation(
    from_agent=researcher_id,
    to_agent=publisher_id,  # Trying to skip Analyst
    task_type="send_email",
    delegation_matrix=delegation_matrix,
)  # Returns False - prevented!

# Create CrewAI agents with governed tools
from crewai import Agent

researcher = Agent(
    role="Researcher",
    tools=[search_tool],
    ...
)

publisher = Agent(
    role="Publisher",
    tools=[email_tool],
    ...
)
```

### Key Features

**1. Agent Identity Management**
```python
# Each agent gets unique cryptographic identity
agent_id = adapter.create_agent_identity("Writer", agent_id="writer-001")
# Returns: "writer-writer-001"
```

**2. Delegation Matrix**
```python
# Define who can delegate to whom
matrix = {
    "manager-id": ["worker1-id", "worker2-id"],
    "worker1-id": [],  # Leaf agent - cannot delegate
}

# Prevents privilege escalation
adapter.validate_delegation("worker1-id", "manager-id", "task", matrix)
# Returns: False
```

**3. Tool Wrapping with Actor Binding**
```python
# Tools are bound to specific agent identities
tool = adapter.wrap_tool(
    name="dangerous_operation",
    func=dangerous_fn,
    actor="specific-agent-id",  # Only this agent can use this tool
    require_permit=True,
)
```

### Security Model

| Attack Vector | Without Shards-Kernel | With Shards-Kernel |
|---------------|----------------|--------------|
| Privilege Escalation | Agent delegates to more powerful agent | Delegation matrix blocks invalid paths |
| Unauthorized Tool Use | Any agent can use any tool | Tools bound to agent identities |
| No Audit Trail | No record of agent actions | Complete hash-chained audit log |
| Role Confusion | Agents exceed intended scope | Tools scoped to agent roles |

---

## Integration 2: AutoGPT (Autonomous Agents)

### Overview

[AutoGPT](https://agpt.co/) was one of the first autonomous AI agent frameworks, capable of running in continuous loops to achieve goals. It can execute shell commands, write files, browse the web, and manage its own memory.

**Governance Challenges:**
- **Autonomous loops** can run indefinitely consuming resources
- **No safety limits** on iterations or runtime
- **Unchecked execution** of dangerous commands
- **No kill-switch** to halt unsafe behavior

### Architecture

```
AutoGPT Autonomous Loop
┌───────────────────────────────┐
│  1. Generate plan (LLM)       │
│  2. Select action             │
│  3. Execute command ───┐      │
│  4. Store result       │      │
│  5. Evaluate progress  │      │
│  6. Repeat or exit     │      │
└────────────────────────┼──────┘
                         │
                         ▼
               Shards-Kernel Policy Gate
               ├── Risk scoring (0.0-1.0)
               ├── Permit verification
               ├── Loop monitoring
               └── Kill-switch activation
```

### Quick Start

```python
from shards_kernel.integrations import AutoGPTAdapter

# Create adapter with autonomous loop monitoring
adapter = AutoGPTAdapter(
    kernel=kernel,
    actor="autogpt-agent",
    enable_monitoring=True,
    max_autonomous_iterations=100,    # Kill-switch after 100 steps
    max_runtime_seconds=3600,          # Kill-switch after 1 hour
)

# Wrap commands with risk scores
@adapter.governed_command("execute_shell", risk_score=1.0)  # CRITICAL
def execute_shell(command: str) -> str:
    return os.popen(command).read()

@adapter.governed_command("browse_website", risk_score=0.3)  # LOW
def browse_website(url: str) -> str:
    return requests.get(url).text

# Execute with governance
try:
    result = execute_shell(
        command="rm -rf /tmp/cache",
        permit_token=permit,  # Requires cryptographic permit
    )
except PermissionError:
    print("Denied - permit required for shell execution")

# Autonomous loop monitoring
if adapter.monitor.should_halt():
    halt_reason = adapter.monitor.get_halt_reason()
    print(f"Kill-switch activated: {halt_reason}")
```

### Risk Scoring

Commands are scored on a 0.0-1.0 scale:

| Risk Level | Score Range | Examples | Permit Required |
|------------|-------------|----------|-----------------|
| **LOW** | 0.0-0.3 | browse_website, read_file | Optional |
| **MEDIUM** | 0.4-0.6 | make_api_call, create_report | Recommended |
| **HIGH** | 0.7-0.9 | write_file, send_email, delete_file | Required |
| **CRITICAL** | 1.0 | execute_shell, execute_python | Required + Audit |

```python
# Set custom risk scores
adapter.set_risk_score("my_command", 0.8)  # HIGH RISK

# Get risk score
risk = adapter.get_risk_score("my_command")  # Returns 0.8
```

### Kill-Switch Configuration

```python
from shards_kernel.integrations.autogpt_adapter import AutonomousLoopMonitor

monitor = AutonomousLoopMonitor(
    max_iterations=100,           # Halt after 100 autonomous steps
    max_runtime_seconds=3600,     # Halt after 1 hour
    max_denials=10,               # Halt after 10 denied operations
    require_permit_after_denials=3,  # Escalate after 3 denials
)

# Check if should halt
if monitor.should_halt():
    reason = monitor.get_halt_reason()
    # Reasons: "Maximum iterations reached", "Maximum runtime exceeded", etc.
```

### Monitoring Statistics

```python
# Access autonomous loop stats
stats = adapter.monitor.stats

print(f"Total iterations: {stats.total_iterations}")
print(f"Commands executed: {stats.commands_executed}")
print(f"Commands denied: {stats.commands_denied}")
print(f"High-risk actions: {stats.high_risk_actions}")
print(f"Runtime: {stats.last_action_time - stats.start_time}s")

# Export with autonomous stats
evidence = adapter.export_evidence()
loop_stats = evidence["autonomous_loop_stats"]
```

---

## Integration 3: LangGraph (Stateful Workflows)

### Overview

[LangGraph](https://www.langchain.com/langgraph) is an extension of LangChain for building stateful, multi-step agent workflows. It enables conditional routing, cycles, and persistent state across workflow execution.

**Governance Challenges:**
- **Invalid state transitions** can violate business logic
- **No authorization** for critical workflow steps
- **State mutations** are not audited
- **Workflows continue** past errors or constraint violations

### Architecture

```
LangGraph Workflow
┌─────────────┐
│ Validate    │ (state: order_details)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Process Pay │ (state: payment_processed = true)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Update Inv  │ (state: inventory -= quantity)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Ship Order  │ (state: order_shipped = true)
└─────────────┘

Shards-Kernel Governance:
├── Node execution permits
├── State transition tracking
├── Workflow invariants enforcement
└── Rollback on violations
```

### Quick Start

```python
from shards_kernel.integrations import LangGraphAdapter

# Create adapter with invariant enforcement
adapter = LangGraphAdapter(
    kernel=kernel,
    actor="workflow-agent",
    enforce_invariants=True,
)

# Define workflow invariants
adapter.add_invariant(
    name="budget_limit",
    description="Total price must not exceed customer budget",
    validator=lambda state: state["total_price"] <= state["budget"],
    enforce=True,  # Halt workflow if violated
)

adapter.add_invariant(
    name="payment_before_shipping",
    description="Payment must be processed before shipping",
    validator=lambda state: (
        not state.get("shipped", False) or
        state.get("payment_processed", False)
    ),
    enforce=True,
)

# Wrap workflow nodes
def process_payment(state: dict) -> dict:
    # Process payment logic
    state["payment_processed"] = True
    return state

governed_payment = adapter.wrap_node(
    "process_payment",
    process_payment,
    require_permit=True,  # HIGH RISK
)

# Execute with permit
new_state = governed_payment(
    state=current_state,
    permit_token=payment_permit,
)

# Invariants are checked before and after execution
# Violations halt workflow with clear error messages
```

### Workflow Invariants

Invariants are conditions that must hold throughout workflow execution:

```python
# Example invariants

# Resource constraints
adapter.add_invariant(
    "positive_inventory",
    "Inventory levels must remain non-negative",
    lambda state: all(qty >= 0 for qty in state["inventory"].values()),
)

# Business logic
adapter.add_invariant(
    "approval_required",
    "Orders over $10k require approval",
    lambda state: (
        state["total_price"] < 10000 or
        state.get("approved_by") is not None
    ),
)

# Temporal constraints
adapter.add_invariant(
    "same_day_shipping",
    "Orders must ship within 24 hours",
    lambda state: (
        not state.get("shipped") or
        state["ship_time"] - state["order_time"] <= 86400
    ),
)
```

### State Transition Tracking

```python
# Get all state transitions
transitions = adapter.get_transitions()

for t in transitions:
    print(f"{t.from_node} → {t.to_node}")
    print(f"  Timestamp: {t.timestamp_ms}")
    print(f"  Was allowed: {t.was_allowed}")
    print(f"  Permit verified: {t.permit_verified}")
    print(f"  State before: {t.state_before}")
    print(f"  State after: {t.state_after}")

# Export with workflow-specific data
evidence = adapter.export_evidence()
workflow_data = evidence["workflow_data"]

# Includes: nodes, transitions, invariants
```

---

## Cross-Framework Patterns

### Pattern 1: Unified Permit Issuance

All frameworks use the same permit format:

```python
from shards_kernel.permits import PermitBuilder

permit = (
    PermitBuilder()
    .issuer("operator@company.com")
    .subject("agent-or-workflow-id")
    .jurisdiction("default")
    .action("tool_or_node_name")
    .params({"key": "value"})  # Must match execution params
    .max_executions(1)
    .valid_from_ms(0)
    .valid_until_ms(1000000)
    .build(keyring, "operator-key-2026")
)
```

### Pattern 2: Evidence Export

All adapters provide `export_evidence()`:

```python
evidence = adapter.export_evidence()

# Standard fields (all frameworks):
evidence["kernel_id"]
evidence["entry_count"]
evidence["root_hash"]
evidence["entries"]

# Framework-specific fields:
evidence["workflow_data"]          # LangGraph
evidence["autonomous_loop_stats"]  # AutoGPT
evidence["multi_agent_data"]       # CrewAI (conceptual)
```

### Pattern 3: Tool/Node Wrapping

Consistent wrapping pattern across frameworks:

```python
# LangChain
governed_tool = langchain_adapter.wrap_tool("name", func)

# CrewAI
governed_tool = crewai_adapter.wrap_tool("name", func)

# AutoGPT
governed_cmd = autogpt_adapter.wrap_command("name", func)

# LangGraph
governed_node = langgraph_adapter.wrap_node("name", func)

# All support:
# - Automatic registration in kernel
# - Permit-based authorization
# - Audit trail generation
```

---

## Production Deployment

### 1. Choose Kernel Variant

```python
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.variants.permissive_kernel import PermissiveKernel

# StrictKernel: Deny by default (recommended for production)
kernel = StrictKernel()

# PermissiveKernel: Allow by default (development/testing)
kernel = PermissiveKernel()
```

### 2. Configure Keyring

```python
# Production: Use secure key management (HSM, KMS, etc.)
from your_kms import get_signing_key

keyring = {
    "operator-2026": get_signing_key("operator"),
    "admin-2026": get_signing_key("admin"),
}

kernel.set_keyring(keyring)
```

### 3. Implement Permit Issuance Workflow

```python
# Example: Approval bot

def request_permit(agent_id: str, action: str, params: dict) -> PermitToken:
    """Request permit from human operator or approval system."""

    # Log request
    audit_log.info(f"Permit requested: {agent_id} wants to {action}")

    # Human approval (Slack, PagerDuty, etc.)
    if not await get_human_approval(agent_id, action, params):
        raise PermissionError("Operator denied permit request")

    # Issue permit
    permit = (
        PermitBuilder()
        .issuer("approval-system")
        .subject(agent_id)
        .action(action)
        .params(params)
        .max_executions(1)
        .valid_from_ms(time.time() * 1000)
        .valid_until_ms((time.time() + 3600) * 1000)  # 1 hour
        .build(keyring, "operator-2026")
    )

    return permit
```

### 4. Monitor and Alert

```python
# Periodic audit trail review
evidence = adapter.export_evidence()

for entry in evidence["entries"]:
    # Alert on denials
    if entry["decision"] == "DENY":
        alert_security_team(f"Denied action: {entry}")

    # Alert on high-risk operations
    if "autonomous_loop_stats" in evidence:
        stats = evidence["autonomous_loop_stats"]
        if stats["high_risk_actions"] > threshold:
            alert_security_team(f"High-risk activity spike: {stats}")
```

### 5. Verification in CI/CD

```bash
# Automated verification
python -m shards_kernel.cli.verify audit_trail.json || exit 1

# Expected checks:
# ✓ Hash Chain Integrity
# ✓ Sequence Numbering
# ✓ Permit Enforcement
# ✓ Replay Protection
# ✓ State Transitions (LangGraph)
```

---

## Compliance Mapping

All agent framework integrations support regulatory requirements:

| Requirement | Framework | Shards-Kernel Mechanism |
|-------------|-----------|-------------------|
| **EU AI Act Art. 12** (Record-keeping) | All | Immutable hash-chained audit log |
| **EU AI Act Art. 14** (Human oversight) | All | Cryptographic permit issuance |
| **ISO 42001** (AI Management) | All | Tool/node governance, audit trails |
| **SOC 2** (Security controls) | All | Authorization, authentication, auditing |
| **NIST AI RMF** (Risk management) | AutoGPT | Risk scoring (0.0-1.0) |

See [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for detailed mappings.

---

## Framework Comparison

| Feature | CrewAI | AutoGPT | LangGraph |
|---------|--------|---------|-----------|
| **Paradigm** | Multi-agent | Autonomous loop | Stateful workflow |
| **Main Risk** | Privilege escalation | Resource exhaustion | Invalid state |
| **Shards-Kernel Focus** | Delegation control | Kill-switch | Invariants |
| **Agent Identity** | ✅ Per-agent | ❌ Single agent | ❌ Single workflow |
| **Loop Monitoring** | ❌ N/A | ✅ Iterations/runtime | ❌ N/A |
| **State Validation** | ❌ Stateless | ❌ Stateless | ✅ Invariants |
| **Permit Granularity** | Per-agent per-tool | Per-command | Per-node |
| **Audit Granularity** | Agent interactions | Command executions | State transitions |

---

## Frequently Asked Questions

### Q: Which kernel variant should I use?

**A:** Use `StrictKernel` for production (deny by default). Use `PermissiveKernel` for development/testing.

### Q: Do all tools require permits?

**A:** No. You can mark low-risk tools as `require_permit=False`, but they still go through audit logging.

### Q: Can I use multiple frameworks with one kernel?

**A:** Yes! All adapters work with the same kernel instance and share the audit trail.

```python
langchain_adapter = LangChainAdapter(kernel)
autogpt_adapter = AutoGPTAdapter(kernel)
# Both governed by same kernel, one unified audit log
```

### Q: How do I handle permit expiration?

**A:** Set `valid_until_ms` in PermitBuilder. Expired permits are rejected with `EXPIRED_PERMIT` error.

### Q: Can I customize risk scores for AutoGPT?

**A:** Yes:
```python
adapter.set_risk_score("my_command", 0.9)  # HIGH RISK
```

### Q: What happens when a LangGraph invariant is violated?

**A:** If `enforce=True`, the workflow is halted immediately with a `RuntimeError` explaining which invariant was violated and the current state.

### Q: How do I audit multi-agent CrewAI interactions?

**A:** Export evidence and filter by agent identity:
```python
evidence = adapter.export_evidence()
researcher_actions = [
    e for e in evidence["entries"]
    if e.get("actor") == "researcher-id"
]
```

---

## Resources

### Examples
- `examples/06_langchain_governed_agent.py` - LangChain integration ("47 emails" prevention)
- `examples/07_huggingface_governed_agent.py` - Hugging Face code execution governance
- `examples/08_openclaw_governed_agent.py` - OpenClaw integration
- `examples/09_crewai_multiagent_governance.py` - CrewAI multi-agent governance
- `examples/10_autogpt_autonomous_governance.py` - AutoGPT kill-switch
- `examples/11_langgraph_stateful_governance.py` - LangGraph workflow invariants

### Documentation
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) - Regulatory framework mappings
- [OPENCLAW_INTEGRATION.md](OPENCLAW_INTEGRATION.md) - OpenClaw security guide
- Main README - Architecture and getting started

### Code
- `shards_kernel/integrations/langchain_adapter.py`
- `shards_kernel/integrations/langgraph_adapter.py`
- `shards_kernel/integrations/crewai_adapter.py`
- `shards_kernel/integrations/autogpt_adapter.py`
- `shards_kernel/integrations/huggingface_adapter.py`
- `shards_kernel/integrations/generic_adapter.py`

### External Resources
- [CrewAI Documentation](https://docs.crewai.com/)
- [AutoGPT Project](https://agpt.co/)
- [LangGraph Guide](https://www.langchain.com/langgraph)
- [LangChain Docs](https://docs.langchain.com/)

---

## Summary

Shards-Kernel transforms AI agent frameworks from powerful-but-risky autonomous systems into **governed, auditable, and compliant** production infrastructure:

✓ **Framework-agnostic** - Works with CrewAI, AutoGPT, LangGraph, LangChain, HuggingFace, OpenClaw, and any tool-calling framework
✓ **Permit-based authorization** - Cryptographically signed permits (HMAC-SHA256)
✓ **Complete audit trails** - Immutable hash-chained evidence bundles
✓ **Kill-switch safety** - Autonomous loop monitoring and halt conditions
✓ **State validation** - Workflow invariants enforcement
✓ **Multi-agent control** - Delegation matrices and agent identity
✓ **Compliance-ready** - EU AI Act, ISO 42001, SOC 2, NIST AI RMF

**The future of autonomous agents is governed, not rogue.**

---

*Framework integrations maintained by the Shards-Kernel team. Contributions welcome.*
