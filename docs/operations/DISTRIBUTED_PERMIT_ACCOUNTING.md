# Distributed permit accounting and external-effect recovery (experimental)

**Status:** implementation is an opt-in PostgreSQL reservation and recovery
journal, **not** a supported remote operator or integrated production kernel.
No changes have been made to the existing single-host SQLite execution path.
Do not direct consequential tools through the current reference service.

## Implemented

`shards_kernel.distributed.postgres.PostgresPermitJournal` provides:

- Atomic permit budget consumption and durable `RESERVED` operation intent in
  the **same PostgreSQL transaction**.
- Cross-connection row-level serialization of permit use. Identity is the
  `(issuer, subject, nonce)` tuple, bound permanently to a `permit_id` and
  `max_executions`.
- Unique operation IDs: a duplicate is **never** granted another dispatch.
- A conservative lifecycle: `RESERVED → DISPATCHED → UNKNOWN → SUCCEEDED` or
  `NOT_APPLIED`. A definitive, verified terminal outcome may go directly
  from `DISPATCHED`.
- Recovery listing for incomplete operations. No automatic retries, releases
  of consumed budget, or host-local fallback on database failure.

This journal **does not verify signatures**. The trusted integration must first
verify the signed Ed25519 permit, audience, subject, time, tool, parameters
and operator policy using the existing kernel verifier. Never expose
`reserve` directly as a model-callable tool.

It does not implement the kernel's hash-chained ledger, a globally atomic
integration with the current `BaseKernel` audit write, or independently
authenticated evidence anchors. A `SUCCEEDED` record represents an adapter's
claim backed by its cited evidence; the journal does not contact providers.

## Connection and migration

Use a single strongly consistent PostgreSQL primary (not read-replica or
SQLite files copied between hosts). Provision a restricted database role and
connection pool outside the model environment. Apply the schema explicitly
with a separately privileged migration identity:

```python
import psycopg
from shards_kernel.distributed.postgres import PostgresPermitJournal

journal = PostgresPermitJournal(lambda: psycopg.connect(POSTGRES_DSN))
journal.initialize_schema()  # Migration only; NOT an agent operation
```

Do not put the DSN or credentials in code, prompts, logs or the repo. Under
network partitions, timeouts or database errors, propagate the failure and
deny dispatch. Do not switch to a local fallback ledger.

Example trusted adapter order:

1. Authenticate actor; verify the actual signed permit and canonical request
   against operator policy.
2. Allocate an immutable unique operation ID and canonical request SHA-256.
3. Call `reserve(...)`; proceed only on a fresh `True`. Its database
   commit consumes the global permit budget **before** any external effect.
4. Persist `mark_dispatched(operation_id)` **before** the first network
   request. Stop when it returns `False`.
5. Send the same operation ID as the provider idempotency key only where
   supported; record the provider's receipt independently.
6. On confirmed success, `reconcile(..., outcome="SUCCEEDED", ...)`.
   On authoritative confirmation of nonapplication, use `NOT_APPLIED`.
   On timeout/disconnection/crash, leave `DISPATCHED` or set `UNKNOWN`.
   Investigate the provider's actual state before any human-approved retry.

**Important crash gap:** marking `DISPATCHED` before an API call can leave a
dispatched record even if the call never began. This is intentional:
ambiguous outcomes are **not** evidence of non-execution. The system
conservatively forfeits a permit budget rather than granting a second effect.

## Acceptance

```bash
python -m pip install -e ".[postgres]" pytest
export SHARDS_TEST_POSTGRES_DSN="postgresql://.../isolated_test_db"
python -m pytest tests/test_distributed_postgres_accounting.py -q
```

The test suite exercises true concurrent PostgreSQL connections,
single/multiple budget caps, duplicate operation IDs, nonce collision,
transaction rollback, cross-host-style contention, ambiguous recovery,
provider evidence requirements and database failure. CI uses an ephemeral
PostgreSQL service.

## Still required before production

1. Wire this transactional boundary to actual operator execution such that
   no action can bypass it and the audit/effect intents agree. Do not attempt
   a cross-database pseudo-atomic SQLite/PostgreSQL commit.
2. Add trusted, separately authenticated real provider adapters with provider
   idempotency keys and authoritative outcome queries.
3. Add independently anchored audit commitments and an explicit recovery
   operator with permission separation.
4. Demonstrate on **two real hosts** with network partitions, process kills,
   database failover and crash injection at every transition.
5. Conduct independent security review and record a production GO/NO-GO.

No finite test establishes universal exactly-once external effects.
