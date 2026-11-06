# StrictKernel + PostgreSQL shared permit pilot (opt-in, not production)

This first integration connects `BaseKernel`'s **strict** permit verification and
builtin tool execution to the shared primary PostgreSQL budget introduced in
PR #114. It is an incremental part of issue #115.

## Supported boundary

- Only the `StrictKernel` variant, only explicitly configured via
  `kernel.enable_shared_permit_accounting(journal)` **before** `boot()`.
- Ed25519 v2 permits with pinned public verifiers; no HMAC permits.
- The two pinned, in-process, deterministic builtins `echo` and `add`.
  Replacing their ToolRegistry objects is denied. No arbitrary external tools.
- Signature, audience, actor, params, validity, constraints and jurisdiction
  checks occur in the existing kernel **before** database reservation.
- An accepted operation atomically consumes one budget use **and** inserts a
  durable `RESERVED` record in the PostgreSQL primary before local auditing.
  A subsequent `DISPATCHED` state is committed before builtin execution.
- The local kernel's existing hash-chained audit ledger remains a **separate
  projection**, not an atomically committed globally shared ledger.
- A successful builtin outcome is reconciled using its locally committed audit
  hash as evidence. **This is not sufficient proof for an external provider**.
- PostgreSQL outages propagate and halt the kernel. No SQLite-only fallback,
  no automatic retry of unknown outcomes, no release of spent permit budget.

## Example: trusted programmatic integration

```python
import psycopg
from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.distributed.postgres import PostgresPermitJournal
from shards_kernel.variants.strict_kernel import StrictKernel

journal = PostgresPermitJournal(lambda: psycopg.connect(DB_DSN))
# Separately privileged migration process only:
# journal.initialize_schema()
kernel = StrictKernel()
kernel.enable_shared_permit_accounting(journal)
kernel.boot(KernelConfig(
    kernel_id="approved-operator-audience", variant="strict",
    clock=VirtualClock(1000),  # TEST ONLY; use a persistent trusted clock in deployment
))
# An independently configured and authenticated operator MUST set a
# restrictive JurisdictionPolicy and pinned Ed25519 public verifiers before
# accepting any request. Authenticate network principal separately.
```

No new CLI flags, public service endpoints or deployment credentials are
introduced. This API must not be treated as a remote operator: a caller in the
same Python process can control policy and kernel state.

## Test evidence

The CI PostgreSQL service runs
`tests/test_distributed_kernel_execution.py` against an actual PostgreSQL
primary, including competing strict kernels, key rejection, changed registry
handlers, DB failure and crash windows. The original local E2E gate, seven
Python versions, branch coverage, Codecov patch and independent PR approval
remain mandatory.

## What remains before a GO decision

1. Global authoritative audit hash chain/checkpoint **in the same PostgreSQL
   transaction** as the permit reservation and a verified external anchor.
   A local SQLite audit record is not a distributed shared audit.
2. Integrate authenticated, signed operator ingress with revocation,
   trust-root rotation, TLS key lifecycle and strict privilege separation.
3. Implement a vetted, nonfinancial real-world provider adapter with
   provider-enforced idempotency and independent outcome reconciliation.
4. Execute two distinct OS-host failure and recovery drills, including
   primary failover, lost acknowledgements, clock rollback, journal recovery
   and backup restoration; preserve report artifacts.
5. Signed/deployed images with provenance, least-privilege DB roles,
   secrets management, incident runbooks, bounded retry decisions and
   evidence-backed GO/NO-GO.

The package must remain marked **NOT_READY** for consequential distributed
external effects until these are verified. Existing single-host CLI and SQLite
semantics remain unchanged.
