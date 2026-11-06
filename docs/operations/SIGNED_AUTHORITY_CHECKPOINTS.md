# Signed external authority checkpoints (experimental)

## Purpose

A database-local hash chain detects tampering with its events but cannot
detect a **wholesale rollback to an internally consistent older snapshot**.
Operators therefore need an independently retained and authenticated
checkpoint: the global authority sequence and root, signed by an identity
whose private key is **outside the AI-agent runtime and primary database**.

`shards_kernel.distributed.checkpoint` provides the offline signing and
verification primitives. It does **not** store a checkpoint remotely, perform
provider reconciliation, deploy key custody, or turn the kernel production
ready. It can be exercised independently of the PostgreSQL audit PR #119.

## Trust and authority boundary

A trusted operator obtains `(sequence, root)` from a **verified**
`PostgresPermitJournal.verify_authority_audit()` result, transfers those
values to the independent signing system, and calls
`sign_checkpoint(...)` using a separately held Ed25519 private key.

The checkpoint includes a namespace/environment, sequence, SHA-256 root,
issuance timestamp, public-key ID, the previous signed checkpoint digest,
and a domain-separated Ed25519 signature. All fields are integrity-protected
by the signature. One may retain the canonical JSON in externally
administered append-only storage, but **this package does not provide the
storage receipt or offsite delivery**.

The independent verifier loads the trusted **public** key mapping,
minimum accepted sequence, full retained signed checkpoint history, and
expected environment from a trust source **outside** PostgreSQL. The
verifier is never permitted to load its trust keys or minimum watermark from
the database whose rollback is being investigated.

```python
from shards_kernel.distributed.checkpoint import (
    SignedAuthorityCheckpoint, sign_checkpoint,
    verify_checkpoint_chain, verify_snapshot_against_checkpoint,
)

# OFFLINE SIGNER ONLY — private key provisioned by the operator, never
# available to AI agents or committed to the repository.
signed = sign_checkpoint(
    sequence=VERIFIED_PRIMARY_SEQUENCE,
    root=VERIFIED_PRIMARY_ROOT,
    environment="staging-operator-a",
    issued_at_ms=TRUSTED_CLOCK_MILLISECONDS,
    key_id="trusted-anchor-signer-v1",
    private_key=OFFLINE_ED25519_PRIVATE_KEY,
    previous=LAST_EXTERNALLY_VERIFIED_CHECKPOINT_OR_NONE,
)
checkpoint_json = signed.as_json()
# Hand the JSON to an independent append-only retention system. This
# example DOES NOT claim that offsite delivery happened.

# INDEPENDENT VERIFIER — trust data and checkpoint JSON retrieved off-host.
checkpoints = [SignedAuthorityCheckpoint.from_json(item) for item in RETAINED_JSON]
latest = verify_checkpoint_chain(
    checkpoints,
    trusted_keys=OUT_OF_BAND_PINNED_PUBLIC_KEYS,
    expected_environment="staging-operator-a",
    minimum_sequence=OPERATOR_PINNED_SEQUENCE,
)
verify_snapshot_against_checkpoint(
    sequence=PRIMARY_SEQUENCE,
    root=PRIMARY_ROOT,
    checkpoint=latest,
    trusted_keys=OUT_OF_BAND_PINNED_PUBLIC_KEYS,
    expected_environment="staging-operator-a",
)
```

The last comparison intentionally accepts **only an exact sequence/root**
match. If the primary is *ahead* of the latest anchored checkpoint, it
fails closed: verifying that the old anchor is a true historical prefix
requires an independently verified event inclusion proof, **not merely a
larger current sequence number**. Do not disable this check in production.

## Required operations before production acceptance

1. Use an offline signing system or HSM/KMS-backed identity separate from
   the kernel, primary DB, tool adapters and AI model runtime. Configure
   authority-owned, monitored key rotation and emergency revocation.
2. Configure real external append-only/WORM/object-lock storage or an
   independently administered audit repository with storage receipts.
   Restrict who can delete, rewrite or shorten retention. Test recovery
   when both primary and local backups are rolled back.
3. Integrate historical anchor inclusion verification with PR #119's global
   hash chain, including restore/failover under network partition.
4. Enforce the last accepted anchor watermark in trusted configuration;
   never bootstrap `minimum_sequence=0` from a possibly stale DB after
   first deployment.
5. Test independently managed clock/timestamp validation, disaster
   recovery, key rotation, lost signer and alarm/halts on mismatch.
6. Produce immutable signed staging evidence and obtain a separate
   operational GO/NO-GO decision. No real financial side-effect tools.

## Reproducible local tests

```bash
python -m pip install -e ".[crypto]" pytest
python -m pytest -q tests/test_signed_authority_checkpoint.py
```

**This is not universal exactly-once execution or an external storage
integration.** Shards-Kernel remains NOT_READY for consequential remote
actions until the full issue #118 production release envelope passes.
