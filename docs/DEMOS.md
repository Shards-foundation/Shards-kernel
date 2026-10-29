# KERNELS Demos

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
python examples/03_sqlite_evidence_archive.py
```

### 01 — Minimal request

Boots a strict kernel, submits an intent-only request, prints the receipt, and
exports the evidence bundle.

### 02 — Verify evidence

Submits a deterministic request and independently recomputes the exported
hash chain. The process exits non-zero if verification fails.

### 03 — SQLite evidence archive

Writes an exported evidence bundle to the SQLite storage helper, opens a new
storage instance, reads the records back, and verifies the chain and root hash.
The temporary database is removed when the demo exits.

**Important boundary:** demo 03 archives evidence after the kernel operation.
The current kernel does not inject this SQLite helper into its live audit
ledger. Do not treat this example as proof of durable audit-before-execution.
That integration, crash-consistency testing, and recovery semantics remain
separate production-hardening work.

## Expected behaviour

Each demo exits with status 0 when its demonstrated operation succeeds. A
failed evidence verification or incomplete archive exits non-zero. Output hashes
are generated at runtime and are not expected to be constant across code or
configuration changes.
