# State Machine Specification

**Version:** 0.1.0

## 1. State Definitions

The kernel state machine defines eight states: BOOTING, IDLE, VALIDATING, ARBITRATING, EXECUTING, AUDITING, COMPLETED, and HALTED. A conforming implementation MUST support all of them. HALTED is the only terminal state. COMPLETED records that one request has finished; it is not terminal, and the kernel returns to IDLE unless it halts.

### 1.1 BOOTING

**Description:** Kernel is initializing and loading configuration.

**Entry Conditions:**
- Kernel instantiation

**Exit Conditions:**
- Configuration loaded successfully → IDLE
- Configuration load failure → HALTED

**Invariants:**
- No requests SHALL be accepted in BOOTING state
- Duration SHOULD be minimal

### 1.2 IDLE

**Description:** Kernel is ready to accept requests.

**Entry Conditions:**
- Successful boot from BOOTING
- Request finished from COMPLETED

**Exit Conditions:**
- Request received → VALIDATING
- Halt command → HALTED

**Invariants:**
- Kernel MUST accept requests only in IDLE state
- No pending operations SHALL exist in IDLE state

### 1.3 VALIDATING

**Description:** Kernel is checking request structure and required fields.

**Entry Conditions:**
- Request submitted from IDLE

**Exit Conditions:**
- Validation passed → ARBITRATING
- Validation failed → AUDITING (with DENY)
- Fatal error → HALTED

**Invariants:**
- Validation MUST be deterministic
- Validation MUST NOT have side effects

### 1.4 ARBITRATING

**Description:** Kernel is evaluating jurisdiction policy and making decision.

**Entry Conditions:**
- Validation passed from VALIDATING

**Exit Conditions:**
- Decision ALLOW with tool_call → AUDITING, so an intent record is durable before execution
- Decision ALLOW without tool_call → AUDITING
- Decision DENY → AUDITING
- Decision HALT → HALTED

The transition matrix still lists ARBITRATING → EXECUTING. The kernel does not use that edge. EXECUTING is reached only from AUDITING, after the intent record has been appended.

**Invariants:**
- Arbitration MUST evaluate all policy rules
- Arbitration MUST NOT modify request

### 1.5 EXECUTING

**Description:** Kernel is dispatching tool call and capturing result.

**Entry Conditions:**
- Intent audit record appended from AUDITING, and the parameters about to run are the parameters the permit authorised

**Exit Conditions:**
- Execution complete → AUDITING
- Execution failure → AUDITING (with error)
- Fatal error → HALTED

**Invariants:**
- Execution MUST be synchronous
- Execution MUST capture result or error

### 1.6 AUDITING

**Description:** Kernel is writing audit entry for completed operation.

**Entry Conditions:**
- Validation failure from VALIDATING
- Arbitration complete from ARBITRATING
- Execution complete from EXECUTING

**Exit Conditions:**
- Intent record appended and a tool is authorised → EXECUTING
- Outcome record appended → COMPLETED
- Audit failure → HALTED

**Invariants:**
- An intent record MUST be appended before EXECUTING. If that append fails, the tool MUST NOT run.
- The outcome record MUST describe the parameters that actually executed.
- Audit failure MUST halt the kernel. AUDITING does not return directly to IDLE.

### 1.7 COMPLETED

**Description:** The request has been audited. The kernel is about to accept another request.

**Entry Conditions:**
- Outcome audit record appended from AUDITING

**Exit Conditions:**
- Request finished → IDLE
- Halt command or fatal error → HALTED

**Invariants:**
- COMPLETED is not a terminal state
- The kernel MUST NOT accept a new request until it has returned to IDLE

### 1.8 HALTED

**Description:** Terminal state, no further operations permitted.

**Entry Conditions:**
- Halt command from any non-terminal state
- Fatal error from any state
- Boot failure from BOOTING

**Exit Conditions:**
- None (terminal state)

**Invariants:**
- No operations SHALL be permitted in HALTED state
- HALTED state MUST be irrevocable

## 2. Transition Matrix

The following matrix defines all allowed transitions. An X indicates the transition is allowed.

| From \ To    | BOOTING | IDLE | VALIDATING | ARBITRATING | EXECUTING | AUDITING | COMPLETED | HALTED |
|--------------|---------|------|------------|-------------|-----------|----------|-----------|--------|
| BOOTING      | -       | X    | -          | -           | -         | -        | -         | X      |
| IDLE         | -       | -    | X          | -           | -         | -        | -         | X      |
| VALIDATING   | -       | -    | -          | X           | -         | X        | -         | X      |
| ARBITRATING  | -       | -    | -          | -           | X         | X        | -         | X      |
| EXECUTING    | -       | -    | -          | -           | -         | X        | -         | X      |
| AUDITING     | -       | -    | -          | -           | X         | -        | X         | X      |
| COMPLETED    | -       | X    | -          | -           | -         | -        | -         | X      |
| HALTED       | -       | -    | -          | -           | -         | -        | -         | -      |

## 3. Transition Rules

### 3.1 General Rules

1. A transition MUST NOT occur unless explicitly defined in the transition matrix.
2. Every transition MUST produce an audit entry (except BOOTING → IDLE).
3. Transitions MUST be atomic with respect to state.
4. The HALTED transition MUST be available from any non-terminal state.

### 3.2 Error Handling

1. Unhandled exceptions MUST result in transition to HALTED.
2. Recoverable errors MUST result in transition to AUDITING with error recorded.
3. The kernel MUST NOT remain in an intermediate state after an error.

### 3.3 Determinism

1. Given the same current state and input, the same transition MUST occur.
2. Transition selection MUST NOT depend on external factors.
3. Time-based decisions MUST use the virtual clock.

## 4. State Diagram

```
                              ┌─────────┐
                              │ BOOTING │
                              └────┬────┘
                                   │
                         success   │   failure
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
              ┌─────────┐                   ┌─────────┐
         ┌───►│  IDLE   │                   │ HALTED  │
         │    └────┬────┘                   └─────────┘
         │         │                              ▲
         │         │ submit()                     │
         │         ▼                              │
         │  ┌────────────┐                        │
         │  │ VALIDATING │────────────────────────┤
         │  └─────┬──────┘     failure            │
         │        │                               │
         │        │ success                       │
         │        ▼                               │
         │  ┌────────────┐                        │
         │  │ARBITRATING │────────────────────────┤
         │  └─────┬──────┘     HALT               │
         │        │                               │
         │        │ ALLOW                         │
         │        ▼                               │
         │  ┌────────────┐     intent appended    │
         │  │  AUDITING  │────────────────────────┤
         │  └─────┬──────┘                        │
         │        │ tool authorised               │
         │        ▼                               │
         │  ┌────────────┐                        │
         │  │ EXECUTING  │────────────────────────┤
         │  └─────┬──────┘     failure            │
         │        │                               │
         │        │ outcome appended              │
         │        ▼                               │
         │  ┌────────────┐                        │
         │  │  AUDITING  │                        │
         │  └─────┬──────┘                        │
         │        ▼                               │
         │  ┌────────────┐                        │
         └──│ COMPLETED  │────────────────────────┘
            └────────────┘     failure
```

## 5. Implementation Requirements

### 5.1 State Storage

1. Current state MUST be stored in a single location.
2. State MUST NOT be inferred from other variables.
3. State changes MUST be explicit assignments.

### 5.2 Transition Enforcement

1. All state changes MUST go through a transition function.
2. The transition function MUST validate the transition is allowed.
3. Invalid transitions MUST raise StateError.

### 5.3 Concurrency

1. State transitions MUST be serialized.
2. Concurrent access to state MUST be prevented.
3. A kernel instance MUST NOT be shared across threads without synchronization.
