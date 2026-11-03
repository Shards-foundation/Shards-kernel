# Jurisdiction Specification

**Version:** 0.1.0

## 1. Overview

Jurisdiction defines the boundaries within which requests are permitted. A conforming implementation MUST evaluate jurisdiction policy before allowing execution.

## 2. Policy Structure

### 2.1 JurisdictionPolicy

A JurisdictionPolicy MUST contain the following fields:

| Field              | Type            | Default                    | Description                    |
|--------------------|-----------------|----------------------------|--------------------------------|
| allowed_actors     | Set[string]     | empty                      | Actors permitted to submit     |
| allowed_tools      | Set[string]     | empty                      | Tools permitted for invocation |
| allowed_states     | Set[KernelState]| operational states         | States allowing requests       |
| required_fields    | Set[string]     | {request_id, actor, intent}| Required request fields        |
| max_param_bytes    | integer         | 65536                      | Maximum parameter size         |
| max_intent_length  | integer         | 4096                       | Maximum intent length          |
| allow_intent_only  | boolean         | false                      | Allow requests without tool_call|

### 2.2 Wildcards

The special value `*` in allowed_actors or allowed_tools indicates all values are permitted.

## 3. Policy Evaluation

### 3.1 Evaluation Order

Policy MUST be evaluated in the following order:

1. Required fields check
2. Actor check
3. Tool check
4. Parameter size check
5. Intent length check
6. Tool call structure check

### 3.2 Required Fields Check

For each field in required_fields:
- If field is missing or empty, the check MUST fail
- The check MUST produce a violation message identifying the field

### 3.3 Actor Check

- If allowed_actors contains `*`, all actors are permitted
- Otherwise, actor MUST be in allowed_actors
- If actor is not permitted, the check MUST fail

### 3.4 Tool Check

- If tool_call is None and allow_intent_only is true, the check passes
- If tool_call is None and allow_intent_only is false, the check MUST fail
- If allowed_tools contains `*`, all tools are permitted
- Otherwise, tool_call.name MUST be in allowed_tools
- If tool is not permitted, the check MUST fail

The convenience `JurisdictionPolicy.default()` explicitly allows intent-only
requests to preserve its historical behavior. An explicit policy with
`allow_intent_only=false` requires a tool call.

### 3.5 Parameter Size Check

- Serialize params using deterministic serialization
- If serialized size exceeds max_param_bytes, the check MUST fail

### 3.6 Intent Length Check

- If intent length exceeds max_intent_length, the check MUST fail

### 3.7 Tool Call Structure Check

If tool_call is present:
- tool_call.name MUST be a non-empty string
- tool_call.params MUST be a dictionary if present

## 4. Ambiguity Detection

### 4.1 Ambiguity Heuristics

The following conditions MUST be detected as ambiguous:

| Condition                    | Severity | Description                        |
|------------------------------|----------|------------------------------------|
| Empty intent                 | High     | Intent is empty or whitespace-only |
| Overly long intent           | Medium   | Intent exceeds max_intent_length   |
| Empty tool name              | High     | tool_call.name is empty            |
| Invalid params type          | High     | params is not a dictionary         |

### 4.2 Strict vs. Relaxed Mode

In strict mode (default):
- All ambiguity heuristics are applied
- Any ambiguity results in DENY

In relaxed mode:
- Only high-severity heuristics are applied
- Medium-severity conditions may be allowed

### 4.3 Fail-Closed Behavior

When ambiguity is detected:
- The kernel MUST NOT proceed with execution
- The kernel MUST return Decision.DENY
- The kernel MUST record the ambiguity in the audit entry

## 5. Policy Result

### 5.1 PolicyResult Structure

Policy evaluation MUST return a PolicyResult containing:

| Field      | Type         | Description                          |
|------------|--------------|--------------------------------------|
| allowed    | boolean      | Whether the request is permitted     |
| violations | List[string] | List of policy violation messages    |

### 5.2 Violation Messages

Violation messages MUST:
- Identify the specific rule that was violated
- Include relevant values (e.g., actor name, tool name)
- Be deterministic for the same violation

## 6. Composable Rules

### 6.1 Rule Functions

Each policy check SHOULD be implemented as a composable rule function:

```
check_actor_allowed(request, policy) -> List[string]
check_tool_allowed(request, policy) -> List[string]
check_required_fields(request, policy) -> List[string]
check_param_size(request, policy) -> List[string]
check_intent_length(request, policy) -> List[string]
check_tool_call_structure(request) -> List[string]
```

### 6.2 Rule Composition

The evaluate_policy function MUST:
1. Execute all rule functions
2. Collect all violations
3. Return PolicyResult with allowed=true only if no violations

## 7. Default Policies

### 7.1 Default Policy

The default policy permits all actors and tools:

```
allowed_actors = {"*"}
allowed_tools = {"*"}
```

### 7.2 Strict Policy

The strict policy denies all by default:

```
allowed_actors = {}
allowed_tools = {}
allow_intent_only = false
```

## 8. Policy Immutability

1. JurisdictionPolicy instances MUST be immutable after creation
2. Policy fields MUST use immutable collections (frozenset)
3. Policy changes MUST create new policy instances
