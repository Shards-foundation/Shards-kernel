# Shared PostgreSQL authority audit (experimental)

## Why this change exists

Previously the shared permit adapter atomically committed its permit budget
and operation intent in PostgreSQL, but the kernel's only **hash-chained**
intent/outcome audit was its *separate local* ledger. A crash between the
PostgreSQL commit and local SQLite append left a consumed permit with an
unverifiable local evidence gap. Even when a local append succeeded, it was
not part of a single distributed transaction.

This change appends a **global hash-linked authority audit event inside the
same PostgreSQL transaction** as each successful reservation or effect state
transition. There is no network call or second-database write in between.

The local kernel audit is retained as an additional diagnostic projection.
It is **not** falsely claimed to be atomic with PostgreSQL.

## Commit protocol

1. Independently verify the signed permit, actor, policy, parameters and
   audience **before** entering global accounting.
2. A single PostgreSQL primary transaction inserts the operation,
   serialises nonce budget use and updates `used`, locks the
   `shards_authority_audit_head` singleton, then appends a canonical
   `RESERVED` hash-chain event and advances the head. The **whole**
   transaction commits or rolls back together.
3. Each successful `DISPATCHED`, `UNKNOWN`, `SUCCEEDED` or
   `NOT_APPLIED` state transition updates the operation and appends its
   corresponding authority event in the **same** transaction.
4. Duplicate operation IDs and rejected/exhausted permits never grant a
   dispatch; rejected state transitions do not append fictitious events.
5. `verify_authority_audit()` checks contiguous sequence, event/hash links,
   canonical payloads, head agreement and current operation-state agreement.
   Any pre-migration operation without matching authority evidence renders
   the database **unverifiable**, not silently backfilled.

Every writer serialises on one PostgreSQL row. This deliberately prioritises
consistency over throughput. A sharded chain, replica reads and automatic
database failover are **not supported** without further verification.

## Explicit limits

- The chain is only as trustworthy as its **primary database**, the DB role
  and storage provenance. A privileged actor could rewrite the entire chain
  and head together or replace a backup. This is **not** external
  tamper-evidence or rollback protection.
- A separately administered, signed and timestamped **external root
  checkpoint** is still required before production trust; never accept a
  checkpoint supplied only by the database it is supposed to authenticate.
- Legacy operations created before the audit migration have no authority
  events. The verifier refuses those gaps; operators must archive the old
  database as unverified evidence and provision a **fresh staging authority
  namespace** for the new production-readiness programme. Never fabricate
  retroactive history or delete history to force a passing status.
- The model-facing execution surface is still restricted to the pinned
  deterministic in-process tools `echo` and `add`. No remote provider
  idempotency, effect read-back, high availability, or off-host recovery
  exists merely because this audit has been added.
- The local CLI's SQLite mode is untouched.

## Validation on a disposable PostgreSQL primary

```bash
python -m pip install -e ".[postgres,crypto]" pytest pytest-cov
export SHARDS_TEST_POSTGRES_DSN="postgresql://.../ephemeral_test_db"
python -m pytest -q \
  tests/test_distributed_postgres_accounting.py \
  tests/test_distributed_kernel_execution.py \
  tests/test_distributed_authority_audit.py
```

Acceptance covers simultaneous independent PostgreSQL connections, one-use
permit budget, transaction rollback on audit failure, ordered hash links,
reconciliation state matching and detection of in-place audit modifications.

## Remaining GO/NO-GO gates

- Independently anchored signed audit roots, retention, backup and
  whole-database anti-rollback tests.
- Actually deployed identity-bound ingress and secret/trust-root lifecycle.
- Provider-backed nonfinancial idempotency plus authoritative reconciliation.
- Two physical or independent VM hosts, real network failure injections,
  reboot/restore drills and evidence packages.
- Independent security review, protected branch approval, reproducible wheel
  and a production operator's signed decision.

See issues #115, #116 and #118. **Production readiness remains false.**
