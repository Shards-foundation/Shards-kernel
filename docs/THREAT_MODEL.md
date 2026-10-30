# Threat Model

This document describes the security assumptions, threats, and mitigations for the Shards-Kernel system.

## Trust Boundaries

The system defines the following trust boundaries:

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUSTED ZONE                                │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Operator    │  │ Kernel Code   │  │    Tools      │       │
│  │   (Policy)    │  │ (This Repo)   │  │ (Registered)  │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Trust Boundary
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                               │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │    Agents     │  │   Requests    │  │   External    │       │
│  │               │  │               │  │   Systems     │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Assumptions

The security model assumes:

| Assumption                | Rationale                                        |
|---------------------------|--------------------------------------------------|
| Operator is trusted       | Operator defines policy; malicious policy is out of scope |
| Kernel code is trusted    | Supply chain security is a separate concern      |
| Registered tools are trusted | Tool registration is an operator action       |
| Execution environment is trusted | OS/hardware security is out of scope      |
| Hash algorithm is secure  | SHA-256 is cryptographically secure              |

## Threats and Mitigations

### T1: Malformed Request Injection

**Threat:** An agent submits a malformed request to bypass validation.

**Mitigation:**
- Request validation checks all required fields
- Type checking enforces correct data types
- Size limits prevent resource exhaustion
- Fail-closed semantics deny malformed requests

**Residual Risk:** None if validation is correctly implemented.

### T2: Jurisdiction Bypass

**Threat:** An agent attempts to invoke tools outside its allowed set.

**Mitigation:**
- Jurisdiction policy explicitly lists allowed actors and tools
- Wildcard (`*`) must be explicitly configured
- Policy evaluation occurs before execution
- Denied requests are audited

**Residual Risk:** Misconfigured policy could allow unintended access.

### T3: Ambiguous Request Exploitation

**Threat:** An agent crafts an ambiguous request that could be interpreted in multiple ways.

**Mitigation:**
- Ambiguity heuristics detect common patterns
- Empty or whitespace-only intents are rejected
- Overly long intents are rejected
- Missing tool names in tool_call are rejected
- Fail-closed: ambiguous requests are denied

**Residual Risk:** Novel ambiguity patterns may not be detected.

### T4: Audit Tampering

**Threat:** An attacker attempts to modify the audit ledger to hide activity.

**Mitigation:**
- Append-only ledger prevents modification
- Hash chain detects tampering
- Replay verification validates integrity
- Evidence bundles include root hash

**Residual Risk:** In-memory ledger could be modified by compromised kernel code.

### T5: State Machine Bypass

**Threat:** An attacker attempts to force the kernel into an invalid state.

**Mitigation:**
- State machine enforces allowed transitions
- Invalid transitions raise StateError
- Terminal state (HALTED) has no outgoing transitions
- State assertions verify expected state

**Residual Risk:** None if state machine is correctly implemented.

### T6: Tool Execution Abuse

**Threat:** An agent abuses a tool to perform unintended operations.

**Mitigation:**
- Tools must be explicitly registered
- No dynamic import or eval
- Tool parameters are validated
- Tool execution is synchronous (no background execution)

**Residual Risk:** Malicious tool implementation (trusted zone compromise).

### T7: Denial of Service

**Threat:** An agent submits many requests to exhaust resources.

**Mitigation:**
- Parameter size limits
- Intent length limits
- Synchronous processing (no unbounded queues)

**Residual Risk:** Rate limiting is not implemented; external rate limiting recommended.

### T8: Information Disclosure via Audit

**Threat:** Sensitive information in requests is exposed through audit export.

**Mitigation:**
- Parameters are hashed, not stored in full
- Evidence is hashed, not stored in full
- Audit export is an explicit operator action

**Residual Risk:** Intent field contains request description; may include sensitive data.

## Out of Scope

The following threats are explicitly out of scope:

| Threat                    | Reason                                           |
|---------------------------|--------------------------------------------------|
| Compromised operator      | Operator is in trusted zone                      |
| Supply chain attacks      | Code integrity is a separate concern             |
| Side-channel attacks      | Requires hardware/OS level mitigations           |
| Network attacks           | Transport security is a separate concern         |
| Physical attacks          | Physical security is out of scope                |
| Malicious tools           | Tools are in trusted zone                        |

## Recommendations

### For Operators

1. **Minimize allowed actors and tools.** Use explicit allowlists rather than wildcards.

2. **Review audit logs regularly.** Detect anomalous patterns early.

3. **Implement external rate limiting.** Protect against denial of service.

4. **Secure the execution environment.** Use appropriate OS and network security.

5. **Verify tool implementations.** Ensure registered tools behave as expected.

### For Integrators

1. **Validate evidence bundles.** Always replay and verify before trusting audit data.

2. **Store evidence bundles securely.** Protect exported evidence from tampering.

3. **Implement transport security.** Use TLS for network communication.

4. **Log kernel operations externally.** Maintain independent audit trail.

### For Developers

1. **Do not modify core invariants.** Changes require security review.

2. **Test edge cases thoroughly.** Ensure fail-closed behavior is maintained.

3. **Review all tool implementations.** Tools execute with kernel trust.

4. **Keep dependencies minimal.** Standard library only reduces attack surface.
