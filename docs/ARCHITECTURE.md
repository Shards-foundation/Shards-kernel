# Architecture

This document describes the internal architecture of the Kernels system.

## Overview

Kernels is structured as a layered system with clear separation between components. Each layer has explicit responsibilities and interfaces.

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL VARIANTS                          │
│     StrictKernel | PermissiveKernel | EvidenceFirst | DualChannel│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        BASE KERNEL                              │
│                    (kernels/variants/base.py)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  STATE MACHINE  │ │  JURISDICTION   │ │     AUDIT       │
│ (kernels/state) │ │(kernels/juris.) │ │ (kernels/audit) │
└─────────────────┘ └─────────────────┘ └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        EXECUTION                                │
│                  (kernels/execution)                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        COMMON                                   │
│              Types | Errors | Hashing | Codec                   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### Common Layer

The common layer provides foundational types and utilities used throughout the system.

| Module      | Responsibility                                    |
|-------------|---------------------------------------------------|
| `types.py`  | Core data types: KernelState, KernelRequest, etc. |
| `errors.py` | Exception hierarchy with fail-closed semantics    |
| `hashing.py`| Deterministic hashing functions                   |
| `codec.py`  | Deterministic serialization                       |
| `validate.py`| Request validation and ambiguity detection       |
| `time.py`   | Virtual clock for deterministic time              |

### State Machine

The state machine enforces the kernel lifecycle through explicit state transitions.

**States:**

| State       | Entry Condition              | Exit Condition                |
|-------------|------------------------------|-------------------------------|
| BOOTING     | Kernel instantiation         | Configuration loaded          |
| IDLE        | Boot complete or audit done  | Request received              |
| VALIDATING  | Request submitted            | Validation complete           |
| ARBITRATING | Validation passed            | Decision made                 |
| EXECUTING   | Decision is ALLOW + tool     | Tool execution complete       |
| AUDITING    | Execution or decision done   | Audit entry written           |
| HALTED      | Halt command or fatal error  | Never (terminal)              |

**Transition Rules:**

The state machine enforces that only defined transitions occur. Any attempt to perform an undefined transition raises `StateError`.

### Jurisdiction

The jurisdiction layer evaluates whether requests are permitted under the current policy.

**Policy Components:**

| Component         | Purpose                                       |
|-------------------|-----------------------------------------------|
| `allowed_actors`  | Set of actors permitted to submit requests    |
| `allowed_tools`   | Set of tools permitted for invocation         |
| `allowed_states`  | States in which requests are accepted         |
| `required_fields` | Fields that must be present in requests       |
| `max_param_bytes` | Maximum serialized size of parameters         |
| `max_intent_length`| Maximum length of intent string              |

**Rule Evaluation:**

Rules are evaluated in sequence. Any rule violation results in denial. The evaluation produces a `PolicyResult` containing all violations.

### Audit

The audit layer maintains an append-only ledger of all kernel operations.

**Ledger Properties:**

| Property        | Description                                     |
|-----------------|-------------------------------------------------|
| Append-only     | Entries cannot be modified or deleted           |
| Hash-chained    | Each entry includes hash of previous entry      |
| Deterministic   | Same inputs produce same hashes                 |
| Exportable      | Full ledger can be exported as evidence bundle  |
| Verifiable      | External parties can replay and verify chain    |

**Entry Schema:**

Each audit entry contains:

| Field          | Type          | Description                        |
|----------------|---------------|------------------------------------|
| `prev_hash`    | string        | Hash of previous entry             |
| `entry_hash`   | string        | Hash of this entry                 |
| `ts_ms`        | integer       | Timestamp in milliseconds          |
| `request_id`   | string        | Request identifier                 |
| `actor`        | string        | Actor who submitted request        |
| `intent`       | string        | Intent of the request              |
| `decision`     | Decision      | ALLOW, DENY, or HALT               |
| `state_from`   | KernelState   | State before transition            |
| `state_to`     | KernelState   | State after transition             |
| `tool_name`    | string?       | Tool invoked, if any               |
| `params_hash`  | string?       | Hash of parameters, if any         |
| `evidence_hash`| string?       | Hash of evidence, if any           |
| `error`        | string?       | Error message, if any              |

### Execution

The execution layer handles tool invocation through a registry-based dispatcher.

**Tool Registry:**

Tools must be explicitly registered before use. The registry does not perform dynamic discovery or import-by-name.

**Built-in Tools:**

| Tool   | Parameters        | Return Type | Description              |
|--------|-------------------|-------------|--------------------------|
| `echo` | `text: str`       | `str`       | Returns input unchanged  |
| `add`  | `a: int, b: int`  | `int`       | Returns sum of inputs    |

**Dispatcher:**

The dispatcher validates tool calls before execution and captures results or errors.

### Kernel Variants

Variants implement the `Kernel` protocol with different enforcement postures.

| Variant         | Key Characteristic                              |
|-----------------|-------------------------------------------------|
| Strict          | Maximum enforcement, strict ambiguity           |
| Permissive      | Relaxed thresholds, intent-only allowed         |
| Evidence-First  | Requires evidence field for ALLOW               |
| Dual-Channel    | Requires constraints dict in params             |

## Data Flow

### Request Processing

```
1. Request arrives at kernel.submit()
2. State: IDLE → VALIDATING
3. Validate request structure
4. Check ambiguity heuristics
5. State: VALIDATING → ARBITRATING
6. Evaluate jurisdiction policy
7. Check variant requirements
8. Make decision: ALLOW | DENY | HALT
9. If ALLOW and tool_call present:
   a. State: ARBITRATING → AUDITING
   b. Append an intent audit record. If this append fails, the tool does not run.
   c. State: AUDITING → EXECUTING
   d. Dispatch the tool with the parameters the permit authorised
   e. Capture the result
10. State: → AUDITING
11. Append the outcome audit record for the parameters that actually ran
12. State: AUDITING → COMPLETED → IDLE
13. Return receipt
```

The intent record is appended before the tool runs. With the default ledger this record is process-local; with an injected storage adapter it is committed before the in-memory chain advances. SQLite-backed startup restores and verifies the chain and fails closed on storage or integrity errors. A crash can still affect uncommitted work, and a local database is not an independently protected archive. An ambiguous request is denied even when `KernelConfig.fail_closed` is false. `StateMachine.reset()` can move a bare machine out of `HALTED`; a halted kernel keeps a separate flag and will not accept another request.

### Evidence Export

```
1. Caller invokes kernel.export_evidence()
2. Ledger entries collected
3. Root hash computed (last entry hash)
4. EvidenceBundle constructed
5. Bundle returned to caller
```

### Replay Verification

```
1. Verifier receives evidence bundle
2. Initialize prev_hash to genesis
3. For each entry:
   a. Verify entry.prev_hash == prev_hash
   b. Recompute entry hash from fields
   c. Verify computed == entry.entry_hash
   d. Update prev_hash = entry.entry_hash
4. Verify final prev_hash == root_hash
5. Report validation result
```

## Invariant Enforcement

Each component enforces specific invariants:

| Component    | Invariants Enforced                              |
|--------------|--------------------------------------------------|
| StateMachine | INV-STATE, INV-TRANSITION                        |
| Jurisdiction | INV-JURISDICTION, INV-FAIL-CLOSED                |
| AuditLedger  | INV-AUDIT, INV-HASH-CHAIN, INV-EVIDENCE          |
| Dispatcher   | INV-DETERMINISM, INV-NO-IMPLICIT-ALLOW           |
| BaseKernel   | INV-HALT (halt always available)                 |

## Extension Points

The architecture supports extension through:

1. **New Variants:** Implement `Kernel` protocol, extend `BaseKernel`
2. **New Tools:** Register with `ToolRegistry`
3. **Custom Policies:** Create `JurisdictionPolicy` instances
4. **Custom Rules:** Add rule functions to jurisdiction evaluation

Extensions must not violate core invariants.
