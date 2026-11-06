# Error Model Specification

**Version:** 0.1.0

## 1. Overview

This specification defines the error taxonomy and fail-closed guarantees for the Kernels system.

## 2. Error Taxonomy

### 2.1 Exception Hierarchy

```
KernelError (base)
├── BootError
├── StateError
├── JurisdictionError
├── AmbiguityError
├── ToolError
└── AuditError
```

### 2.2 KernelError

**Description:** Base exception for all kernel errors.

**Properties:**
- message: Human-readable error description
- fail_closed: Boolean indicating fail-closed behavior (default: true)

**Usage:** MUST NOT be raised directly; use specific subclasses.

### 2.3 BootError

**Description:** Raised when kernel fails to boot.

**Causes:**
- Invalid configuration
- Missing required parameters
- Kernel already booted

**Recovery:** Create new kernel instance with valid configuration.

**State Transition:** BOOTING → HALTED

### 2.4 StateError

**Description:** Raised when an invalid state transition is attempted.

**Causes:**
- Transition not in allowed set
- Operation in terminal state
- Unexpected current state

**Recovery:** None within current session; indicates programming error.

**State Transition:** Current → HALTED (if not already terminal)

### 2.5 JurisdictionError

**Description:** Raised when a request fails jurisdiction checks.

**Causes:**
- Actor not in allowed set
- Tool not in allowed set
- Missing required fields
- Parameter size exceeded

**Recovery:** Submit request with valid actor/tool/fields.

**State Transition:** ARBITRATING → AUDITING (with DENY)

### 2.6 AmbiguityError

**Description:** Raised when a request is ambiguous.

**Causes:**
- Empty intent
- Overly long intent
- Empty tool name
- Invalid params type

**Recovery:** Submit request with unambiguous content.

**State Transition:** VALIDATING → AUDITING (with DENY)

### 2.7 ToolError

**Description:** Raised when tool execution fails.

**Causes:**
- Tool not registered
- Invalid parameters
- Execution failure

**Recovery:** Submit request with valid tool and parameters.

**State Transition:** EXECUTING → AUDITING (with FAILED)

### 2.8 AuditError

**Description:** Raised when audit operations fail.

**Causes:**
- Hash computation failure
- Serialization failure
- Chain integrity violation

**Recovery:** None; indicates system failure.

**State Transition:** AUDITING → HALTED

## 3. Fail-Closed Guarantees

### 3.1 Definition

Fail-closed means that when an error or uncertainty occurs, the system denies the operation rather than allowing it.

### 3.2 Guarantees

A conforming implementation MUST provide these guarantees:

| Condition                    | Behavior                              |
|------------------------------|---------------------------------------|
| Malformed request            | DENY                                  |
| Unknown actor                | DENY                                  |
| Unknown tool                 | DENY                                  |
| Ambiguous intent             | DENY                                  |
| Missing required field       | DENY                                  |
| Parameter size exceeded      | DENY                                  |
| Tool execution failure       | FAIL (no result returned)             |
| Unhandled exception          | HALT                                  |
| Audit failure                | HALT                                  |

### 3.3 No Silent Failures

The kernel MUST NOT:
- Silently drop requests
- Return success when operation failed
- Proceed with partial execution
- Ignore errors in audit

## 4. Error Handling Flow

### 4.1 Validation Errors

```
1. Error detected during validation
2. Create error message
3. Transition to AUDITING
4. Record DENY decision with error
5. Transition to IDLE
6. Return receipt with REJECTED status
```

### 4.2 Jurisdiction Errors

```
1. Policy violation detected
2. Collect all violations
3. Transition to AUDITING
4. Record DENY decision with violations
5. Transition to IDLE
6. Return receipt with REJECTED status
```

### 4.3 Execution Errors

```
1. Tool execution fails
2. Capture error message
3. Transition to AUDITING
4. Record DENY decision with error
5. Transition to IDLE
6. Return receipt with FAILED status
```

### 4.4 Fatal Errors

```
1. Unrecoverable error detected
2. Transition to HALTED
3. Record HALT in audit (if possible)
4. Raise exception to caller
```

## 5. Error Messages

### 5.1 Message Requirements

Error messages MUST:
- Be deterministic for the same error
- Include relevant context
- Not expose sensitive information
- Be human-readable

### 5.2 Message Format

```
<ErrorType>: <Description>. <Context>.
```

Examples:
- "JurisdictionError: Actor 'unknown' is not in allowed actors."
- "AmbiguityError: Empty intent is ambiguous."
- "ToolError: Tool 'delete' is not registered."

## 6. Receipt Status Mapping

| Error Type        | Receipt Status | Decision |
|-------------------|----------------|----------|
| Validation error  | REJECTED       | DENY     |
| Jurisdiction error| REJECTED       | DENY     |
| Ambiguity error   | REJECTED       | DENY     |
| Tool error        | FAILED         | DENY     |
| Halt queued (in-flight tool) | QUEUED   | HALT     |
| Halt completed             | ACCEPTED | HALT     |

## 7. Implementation Requirements

### 7.1 Exception Handling

1. All kernel operations MUST be wrapped in try-except
2. Known errors MUST be caught and handled appropriately
3. Unknown errors MUST result in HALT
4. Errors MUST be recorded in audit before state change

### 7.2 Error Propagation

1. Errors MUST NOT be silently swallowed
2. Error details MUST be included in receipt
3. Audit entries MUST include error field when applicable

### 7.3 Testing

1. All error paths MUST have test coverage
2. Tests MUST verify fail-closed behavior
3. Tests MUST verify error messages are deterministic
