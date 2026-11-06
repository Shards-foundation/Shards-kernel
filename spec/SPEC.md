# Kernels Specification

**Version:** 0.1.0  
**Status:** Draft

## 1. Overview

This specification defines the normative requirements for Kernels, a deterministic control plane for AI systems.

### 1.1 Scope

This specification covers:

- Core types and their semantics
- State machine definition and transitions
- Jurisdiction policy evaluation
- Audit ledger structure and verification
- Kernel API surface
- Invariant definitions

### 1.2 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 2. Core Invariants

A conforming implementation MUST satisfy all of the following invariants:

### INV-STATE

The kernel MUST be in exactly one defined state at any time. The defined states are: BOOTING, IDLE, VALIDATING, ARBITRATING, EXECUTING, AUDITING, HALTED.

### INV-TRANSITION

State transitions MUST occur only through defined transition functions. Implementations MUST NOT allow implicit state changes.

### INV-JURISDICTION

Every request MUST pass jurisdiction checks before execution. Requests that fail jurisdiction MUST be denied.

### INV-AUDIT

Every state transition MUST produce an append-only audit entry before the transition completes.

### INV-HASH-CHAIN

Audit entries MUST be hash-chained. Each entry MUST include the hash of the previous entry.

### INV-FAIL-CLOSED

Ambiguous, malformed, or unhandled requests MUST result in DENY or HALT. The kernel MUST NOT proceed under uncertainty.

### INV-DETERMINISM

Given identical inputs and initial state, the kernel MUST produce identical outputs and final state.

### INV-HALT

The kernel MUST immediately close admission to new executions when an operator halt is requested. Halt MUST be irrevocable within a session. If a trusted handler is already executing, its outcome MUST be audited before the terminal `HALTED` transition; a queued halt acknowledgement MUST NOT be represented as terminal completion.

### INV-EVIDENCE

All decisions MUST be exportable as an evidence bundle with verifiable hash chain.

### INV-NO-IMPLICIT-ALLOW

The absence of a DENY is not an ALLOW. Explicit ALLOW decisions MUST be required for execution.

## 3. Types

### 3.1 KernelState

An enumeration of valid kernel states.

| Value       | Description                                |
|-------------|--------------------------------------------|
| BOOTING     | Kernel initializing                        |
| IDLE        | Ready to accept requests                   |
| VALIDATING  | Checking request structure                 |
| ARBITRATING | Evaluating jurisdiction                    |
| EXECUTING   | Dispatching tool call                      |
| AUDITING    | Writing audit entry                        |
| HALTED      | Terminal state                             |

### 3.2 Decision

An enumeration of possible decisions.

| Value | Description                                    |
|-------|------------------------------------------------|
| ALLOW | Request is permitted; execution may proceed    |
| DENY  | Request is rejected; no execution occurs       |
| HALT  | Stop requested; terminal transition may be deferred until the in-flight outcome is audited |

### 3.3 ReceiptStatus

An enumeration of receipt statuses.

| Value    | Description                                   |
|----------|-----------------------------------------------|
| ACCEPTED | Request was processed successfully; a halt with `state_to=HALTED` is terminal |
| QUEUED   | Operator halt acknowledged while a tool remains in-flight; not yet confirmed `HALTED` |
| REJECTED | Request was denied by policy or validation    |
| FAILED   | Request processing encountered an error       |

### 3.4 KernelRequest

A request submitted to the kernel.

| Field      | Type           | Required | Description                    |
|------------|----------------|----------|--------------------------------|
| request_id | string         | Yes      | Unique request identifier      |
| ts_ms      | integer        | Yes      | Timestamp in milliseconds      |
| actor      | string         | Yes      | Actor submitting request       |
| intent     | string         | Yes      | Intent description             |
| tool_call  | ToolCall       | No       | Tool to invoke                 |
| params     | dict           | No       | Additional parameters          |
| evidence   | string         | No       | Supporting evidence            |

### 3.5 KernelReceipt

A receipt returned after processing.

| Field         | Type          | Required | Description                   |
|---------------|---------------|----------|-------------------------------|
| request_id    | string        | Yes      | Request identifier            |
| status        | ReceiptStatus | Yes      | Processing status             |
| state_from    | KernelState   | Yes      | State before processing       |
| state_to      | KernelState   | Yes      | State after processing        |
| ts_ms         | integer       | Yes      | Timestamp in milliseconds     |
| decision      | Decision      | Yes      | Decision made                 |
| error         | string        | No       | Error message if any          |
| evidence_hash | string        | No       | Hash of audit entry           |
| tool_result   | any           | No       | Tool execution result         |

### 3.6 ToolCall

A specification of a tool invocation.

| Field  | Type   | Required | Description              |
|--------|--------|----------|--------------------------|
| name   | string | Yes      | Tool name                |
| params | dict   | No       | Tool parameters          |

### 3.7 AuditEntry

A single entry in the audit ledger.

| Field         | Type        | Required | Description                   |
|---------------|-------------|----------|-------------------------------|
| prev_hash     | string      | Yes      | Hash of previous entry        |
| entry_hash    | string      | Yes      | Hash of this entry            |
| ts_ms         | integer     | Yes      | Timestamp in milliseconds     |
| request_id    | string      | Yes      | Request identifier            |
| actor         | string      | Yes      | Actor who submitted           |
| intent        | string      | Yes      | Intent of request             |
| decision      | Decision    | Yes      | Decision made                 |
| state_from    | KernelState | Yes      | State before transition       |
| state_to      | KernelState | Yes      | State after transition        |
| tool_name     | string      | No       | Tool invoked                  |
| params_hash   | string      | No       | Hash of parameters            |
| evidence_hash | string      | No       | Hash of evidence              |
| error         | string      | No       | Error message                 |

### 3.8 EvidenceBundle

An exportable evidence bundle.

| Field          | Type              | Required | Description              |
|----------------|-------------------|----------|--------------------------|
| ledger_entries | list[AuditEntry]  | Yes      | All audit entries        |
| root_hash      | string            | Yes      | Hash of last entry       |
| exported_at_ms | integer           | Yes      | Export timestamp         |
| kernel_id      | string            | Yes      | Kernel identifier        |
| variant        | string            | Yes      | Kernel variant           |

## 4. Kernel API

A conforming kernel implementation MUST provide the following methods:

### 4.1 boot

```
boot(config: KernelConfig) -> None
```

Initialize the kernel with configuration. MUST transition from BOOTING to IDLE. MUST raise BootError if boot fails.

### 4.2 get_state

```
get_state() -> KernelState
```

Return the current kernel state. MUST NOT modify state.

### 4.3 submit

```
submit(request: KernelRequest) -> KernelReceipt
```

Submit a request for processing. MUST validate request, evaluate jurisdiction, execute if allowed, and produce audit entry. MUST return receipt with decision.

### 4.4 step

```
step() -> KernelReceipt | None
```

Advance the kernel by one step. MUST return receipt if step was taken, None if idle.

### 4.5 halt

```
halt(reason: str) -> KernelReceipt
```

Request an irrevocable halt and stop new admission immediately. When no tool is in flight, return `ReceiptStatus.ACCEPTED` with terminal `state_to=HALTED`. During an in-flight execution, record `HALT_QUEUED` and return `ReceiptStatus.QUEUED` with nonterminal `state_to`, unless terminal completion occurs before the response. The existing tool's outcome MUST be audited before the terminal `HALTED` transition. Clients MUST NOT interpret `Decision.HALT` or a queued receipt alone as proof of completed termination or effect cancellation; query current state and independently reconcile external effects.

### 4.6 export_evidence

```
export_evidence() -> EvidenceBundle
```

Export the audit ledger as evidence. MUST include all entries and root hash.

## 5. Lifecycle

### 5.1 Request Processing

A conforming implementation MUST process requests in the following sequence:

1. Receive request via `submit()`
2. Transition to VALIDATING
3. Validate request structure
4. Check ambiguity heuristics
5. Transition to ARBITRATING
6. Evaluate jurisdiction policy
7. Check variant requirements
8. Make decision
9. If ALLOW and tool_call present, transition to EXECUTING
10. Execute tool call
11. Transition to AUDITING
12. Create audit entry
13. Transition to IDLE
14. Return receipt

### 5.2 Failure Handling

On any failure during processing:

1. MUST NOT proceed with execution
2. MUST produce audit entry with error
3. MUST return receipt with appropriate status
4. MUST return to IDLE or HALTED state

## 6. Verification

### 6.1 Replay Verification

To verify an audit ledger:

1. Initialize prev_hash to genesis hash (64 zeros)
2. For each entry in sequence:
   a. Verify entry.prev_hash equals prev_hash
   b. Recompute entry hash from fields
   c. Verify computed hash equals entry.entry_hash
   d. Set prev_hash to entry.entry_hash
3. Verify final prev_hash equals root_hash

### 6.2 Evidence Bundle Verification

To verify an evidence bundle:

1. Perform replay verification on ledger_entries
2. Verify computed root hash equals bundle.root_hash
