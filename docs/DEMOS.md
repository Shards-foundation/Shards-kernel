# Shards-Kernel Demos

These demos use deterministic clocks and synthetic requests. They do not connect
to external services, invoke real-world tools, or require API keys.

## Requirements

From a repository checkout, install the package and its development extras:

```bash
python -m pip install -e ".[dev]"
```

Python 3.9–3.12 are the supported versions declared by the project.

## Run the demos

```bash
python examples/01_minimal_request.py
python examples/02_verify_evidence.py
python examples/03_fail_closed_ambiguity.py
python examples/04_sqlite_persistent_ledger.py
```

### 01 — Minimal request

Boots a strict kernel, submits an intent-only request, prints the receipt, and
exports the evidence bundle.

### 02 — Verify evidence

Submits a deterministic request and independently recomputes the exported
hash chain. The process exits non-zero if verification fails.

### 03 — Fail-closed ambiguity

Demonstrates that ambiguous or invalid requests do not silently become permission to execute. See the example source for the exact request and expected rejection.

### 04 — Durable SQLite audit ledger

Injects `SQLiteAuditStorage` into the kernel, commits each ledger entry to
SQLite before the in-memory ledger advances, then creates a new kernel instance
against the same database. Boot verifies and restores the persisted hash chain.
The demo fails if the recovered entries or root hash differ. The temporary
database is removed when the demo exits.

This is a local durable-storage implementation, not a distributed database or
an independently tamper-proof archive. Production deployments still need
operational backup/restore drills, filesystem and host security, monitoring,
and external anchoring or signing if resistance to privileged database
rewriting is required.

## Expected behaviour

Each demo exits with status 0 when its demonstrated operation succeeds. A
failed evidence verification or incomplete archive exits non-zero. Output hashes
are generated at runtime and are not expected to be constant across code or
configuration changes.
