# Frequently Asked Questions

## General

### What is Shards-Kernel?

Shards-Kernel is a deterministic control plane for AI systems. It provides a state machine that governs AI agent execution through explicit jurisdiction, append-only audit, and fail-closed semantics.

### What problem does Shards-Kernel solve?

AI systems without deterministic control planes exhibit failure modes including ambiguity propagation, non-deterministic state, unbounded execution, audit gaps, and authority diffusion. Shards-Kernel addresses these by enforcing explicit boundaries and producing immutable audit records.

### Is Shards-Kernel an AI framework?

No. Shards-Kernel is a control plane, not an AI framework. It does not implement AI capabilities. It governs systems that may include AI components.

### Is Shards-Kernel an LLM wrapper?

No. Shards-Kernel does not call language models. It validates and arbitrates requests from systems that may use language models.

## Architecture

### Why is the state machine explicit?

Explicit state machines provide deterministic behavior, enable audit, and prevent implicit state changes that could lead to undefined behavior.

### Why is the audit ledger hash-chained?

Hash chaining provides tamper detection. If any entry is modified, the chain breaks and verification fails.

### Why are there multiple kernel variants?

Different use cases require different enforcement postures. Variants allow operators to choose the appropriate level of strictness for their context.

### Can I create custom kernel variants?

Yes. Implement the `Kernel` protocol and extend `BaseKernel`. Custom variants must satisfy all core invariants.

## Usage

### How do I add a new tool?

Register the tool with the `ToolRegistry`:

```python
from shards_kernel.execution.tools import ToolRegistry

registry = ToolRegistry()
registry.register(
    name="my_tool",
    handler=my_function,
    description="Description of my tool",
    param_schema={"param1": str, "param2": int},
)
```

### How do I configure jurisdiction policy?

Create a `JurisdictionPolicy` and set it on the kernel:

```python
from shards_kernel.jurisdiction.policy import JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=frozenset({"alice", "bob"}),
    allowed_tools=frozenset({"echo", "add"}),
)
kernel.set_policy(policy)
```

### How do I verify an audit ledger?

Use the replay verification functions:

```python
from shards_kernel.audit.replay import replay_and_verify

entries = ledger.to_list()
is_valid, errors = replay_and_verify(entries)
```

### What happens when a request is ambiguous?

In fail-closed mode (default), ambiguous requests are denied. The kernel returns a receipt with `Decision.DENY` and an error message describing the ambiguity.

### Can I recover from HALTED state?

No. HALTED is a terminal state. To continue operations, create a new kernel instance.

## Invariants

### What are the core invariants?

The ten core invariants are:

1. INV-STATE: Single defined state at all times
2. INV-TRANSITION: Only defined transitions occur
3. INV-JURISDICTION: All requests pass jurisdiction checks
4. INV-AUDIT: All transitions produce audit entries
5. INV-HASH-CHAIN: Audit entries are hash-chained
6. INV-FAIL-CLOSED: Ambiguity results in DENY or HALT
7. INV-DETERMINISM: Identical inputs produce identical outputs
8. INV-HALT: Halt is always possible and irrevocable
9. INV-EVIDENCE: Decisions are exportable with verification
10. INV-NO-IMPLICIT-ALLOW: Explicit ALLOW required for execution

### What happens if an invariant is violated?

Invariant violations indicate bugs in the kernel implementation. They should be reported as security issues.

### Can invariants be changed?

Invariant changes require a major version bump, documented consensus, and a migration guide. They are exceptional events.

## Integration

### Does Shards-Kernel require external dependencies?

No. Shards-Kernel uses only the Python 3.11+ standard library.

### Can Shards-Kernel be used with async/await?

The current implementation is synchronous. Async support may be added in future versions.

### How do I integrate Shards-Kernel with my AI system?

1. Create a kernel instance with appropriate variant
2. Configure jurisdiction policy
3. Register any custom tools
4. Submit requests through `kernel.submit()`
5. Process receipts and handle decisions
6. Export evidence for audit

### Can multiple kernels run concurrently?

Yes. Each kernel instance is independent. They do not share state.

## Troubleshooting

### Why is my request being denied?

Check the receipt's `error` field for details. Common causes:

- Actor not in allowed_actors
- Tool not in allowed_tools
- Missing required fields
- Ambiguous intent
- Variant-specific requirements not met

### Why is the hash chain verification failing?

Hash chain failures indicate tampering or corruption. Verify that:

- Entries were not modified after creation
- Entries are in the correct order
- No entries were removed

### Why is my tool not being executed?

Tool execution requires:

- `tool_call` field present in request
- Tool registered in registry
- Tool in allowed_tools policy
- Valid parameters

Check the receipt for specific errors.
