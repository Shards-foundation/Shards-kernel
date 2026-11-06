# Independent Shards-Kernel 0.1.2 verification

This directory is a separate **evidence harness** for the immutable, published
\`shards-kernel==0.1.2\` PyPI wheel, pinned to SHA-256:
\`08dc0df1ade8769a3c9cd7560fd22362e1a313aa78de5d1063c67d64a59fa057\`.

It does not alter source, publish a package, or use network-facing tools. The
GitHub Actions job executes from the runner's temporary directory, deliberately
outside the checked-out source tree, to avoid importing a local checkout.

## Three independently authored probes

- **SK-002 scope omission:** genuine Ed25519 permit, a test-only registered
  \`sink(**kwargs)\`, and evidence of actual received arguments for exact
  versus omitted permit parameters. Positive control is required.
- **SK-001 concurrency:** 1,000 attempts per limit (1, 2, 5, 10), a pool of up
  to 100 threads, independent side-effect counts, ALLOW receipts and exception
  samples. It is **not** 1,000 simultaneously running threads.
- **SK-003 crash window:** real SIGKILL after committing an external SQLite
  effect. The same single-use signed permit is retried in a fresh Python
  process. **In-memory audit** and **SQLiteAuditStorage** are tested separately.
  A duplicate in in-memory mode is an expected limitation; a durable-backed
  duplicate would be an actionable failure.

The \`verify.py\` process always attempts to write machine-readable JSON even
when a probe encounters an error. The \`assert_results.py\` check runs after
artifact upload and deliberately makes the job **red** for violations or
incomplete harnesses. Do not misinterpret a red acceptance gate as a lack of
execution evidence; inspect the uploaded artifact and runner logs.

This is a targeted verification lab, **not** a full production certificate.
It does not establish remote mTLS readiness, MCP correctness, distributed
replay consistency, audited crash-safe exactly-once external execution,
ledger-witness guarantees or production deployment procedures.

## Safety / independence

- Synthetic identities only; no real secrets or private key material in
  uploaded evidence.
- No production endpoints, credentials, funds, privileged actions or remote
  services are exercised.
- Source code and release tags stay unchanged.
- Test conclusions remain hypotheses until complete CI evidence is reviewed.
