# Shards-Kernel — Deterministic Control Planes for AI Systems

[![CI](https://github.com/Shards-foundation/Shards-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Shards-foundation/Shards-kernel/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Shards-foundation/Shards-kernel/branch/main/graph/badge.svg)](https://codecov.io/gh/Shards-foundation/Shards-kernel)

A **kernel** is a deterministic state machine that governs AI agent execution via **jurisdiction**, **fail-closed arbitration**, and an **append-only hash-chained audit ledger**.

**Hard constraint:** no tool execution without an explicit `ALLOW`; no `ALLOW` without a committed audit decision.

---

## Problem (Operational, Not Philosophical)

Ungoverned agent systems fail in predictable ways:

| Failure Mode | Consequence |
|--------------|-------------|
| Ambiguity escapes into execution | Actions occur without a crisp, auditable decision boundary |
| Implicit state drift | Post-hoc analysis becomes narrative, not replay |
| Tool reach exceeds operator intent | "Capability" becomes "authority" |
| Logs are advisory | Missing transitions = missing truth |
| Accountability diffuses | No single place to prove "why this happened" |

Shards-Kernel exists to make those failure modes **structurally expensive** and **forensically obvious**.

---

## Model

```
OPERATOR (authority) ── KernelRequest ──▶ KERNEL (policy+state+audit) ──▶ TOOL REGISTRY
       ▲                                           │
       └───────────── KernelReceipt ◀──────────────┘

AGENT has no direct tool access; it submits requests and receives results.
```

Separation is the point:

| Component | Responsibility | Authority |
|-----------|----------------|-----------|
| Operator | Sets policy, reviews evidence, halts | Highest |
| Kernel | Validates, arbitrates, records | Delegated |
| Tool registry | Executes sanctioned ops | None |
| Agent | Requests + consumes results | None |

---

## Core Invariants (Normative)

A compliant kernel MUST satisfy:

| ID | Invariant | Description |
|----|-----------|-------------|
| INV-STATE | Single state | Exactly one state at any time |
| INV-TRANSITION | Explicit transitions | Transitions only via declared functions |
| INV-JURISDICTION | Policy enforcement | Every request passes policy before execution |
| INV-AUDIT | Audit completeness | Every transition emits an audit entry before completion |
| INV-HASH-CHAIN | Chain integrity | Audit entries chain to previous hash |
| INV-FAIL-CLOSED | Deny on ambiguity | Ambiguity/malformed/unhandled ⇒ `DENY` or `HALT` |
| INV-DETERMINISM | Reproducibility | Identical inputs + initial state ⇒ identical outputs |
| INV-HALT | Halt availability | Immediate halt from any state; terminal for session |
| INV-EVIDENCE | Exportability | Decisions exportable as verifiable evidence bundle |
| INV-NO-IMPLICIT-ALLOW | Explicit permission | "Not denied" ≠ allowed; explicit `ALLOW` required |

---

## State Machine (Canonical)

```
BOOTING → IDLE → VALIDATING → ARBITRATING → AUDITING (intent)
        → EXECUTING → AUDITING (outcome) → COMPLETED → IDLE
Any unhandled exception ────────────────────────────────────────▶ HALTED
```

---

## Public API (Supported Surface)

Treat everything else as internal. Your stable integration points:

```python
from shards_kernel import (
    # Core types
    Kernel,              # Protocol / interface
    KernelRequest,       # Request structure
    KernelReceipt,       # Response structure
    Decision,            # ALLOW | DENY | HALT
    KernelConfig,        # Configuration
    
    # Variants
    StrictKernel,        # Maximum enforcement
    PermissiveKernel,    # Relaxed thresholds
    EvidenceFirstKernel, # Requires evidence field
    DualChannelKernel,   # Requires constraints dict
    
    # Tooling
    ToolRegistry,        # Tool registration + dispatch
    
    # Evidence
    replay_and_verify,   # External verification
    verify_evidence_bundle,
)
```

If a module is not reachable via `shards_kernel.api`, it is **not** a supported API surface.

---

## Kernel Variants

Variants tune posture while preserving invariants:

| Variant | Posture | Key Requirement |
|---------|---------|-----------------|
| **StrictKernel** | Maximal enforcement | Strict ambiguity handling |
| **PermissiveKernel** | Relaxed thresholds | Intent-only allowed |
| **EvidenceFirstKernel** | Evidence-required | `evidence` field mandatory |
| **DualChannelKernel** | Structured constraints | `constraints` dict required |

---

## Install

The PyPI distribution name is `shards-kernel`, the import namespace is `shards_kernel`, and the CLI command is `shards-kernel`:

```bash
python -m pip install shards-kernel  # after the approved PyPI release
python -c "import shards_kernel"
```

A verified PyPI release is pending. The different PyPI project [`kernels`](https://pypi.org/project/kernels/) belongs to Hugging Face. Do **not** install `kernels` when intending to install Shards-Kernel. Until the approved release, install this repository from GitHub:

```bash
python -m pip install "git+https://github.com/Shards-foundation/Shards-kernel.git"
```

Or clone it and install the checkout in editable mode:

```bash
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel
python -m pip install -e .
```

Both approaches provide `import shards_kernel` and the `shards-kernel` command.

## Quickstart

```bash
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel
python -m pip install -e .
python -m unittest discover -s tests -v
bash scripts/smoke.sh
python examples/01_minimal_request.py
python -m shards_kernel --help
```

## Runnable Demos

The repository includes deterministic, offline examples for request handling,
fail-closed decisions, evidence verification, and durable SQLite audit recovery. Start with
[the demo guide](docs/DEMOS.md).

```bash
python -m pip install -e ".[dev]"
python examples/01_minimal_request.py
python examples/02_verify_evidence.py
python examples/03_fail_closed_ambiguity.py
python examples/04_sqlite_persistent_ledger.py
```

The SQLite demo injects a SQLite-backed audit ledger into the kernel and checks
that verified evidence is restored after restart. See the demo guide for the
scope and operational limitations.

## Organisation-wide repository review automation

Use the helper below to clone every repository in a GitHub organisation, run
standard quality checks, and export machine-readable + markdown summaries.

```bash
export GITHUB_TOKEN=ghp_xxx   # token with access to your organisation repos
python scripts/org_repo_review.py --org Shards-foundation
```

Outputs:
- `reports/org-review.json` with full command output and exit codes.
- `reports/org-review.md` with per-repo pass/fail status.

## Autonomous Codex contribution scaffold

Local scripts under `scripts/agents/` support a closed-loop contribution
workflow. `.github/workflows/codex-pr-generator.yml` and
`.github/workflows/codex-self-heal.yml` are not in this repository. The workflow
files that are present are:

- `.github/workflows/ci.yml`
- `.github/workflows/dependency-canary.yml`
- `.github/workflows/dependency-health.yml`
- `.github/workflows/docs.yml`
- `.github/workflows/jekyll-gh-pages.yml`
- `.github/workflows/release.yml`
- `.github/workflows/security.yml`
- `.github/workflows/smoke.yml`
- `.github/workflows/static.yml`

The local scripts are:

- `scripts/agents/codex_generate_patch.py` writes auditable run payloads to
  `.codex/runs/`.
- `scripts/agents/build_codex_prompt.py` injects kernel skill constraints from
  `skills/` into an agent-ready prompt payload with failure-aware routing.
- `scripts/agents/append_metrics.py` attaches benchmark deltas to each run.
- `scripts/agents/evaluate_run.py` scores runs and updates
  `.codex/meta/leaderboard.json` and `.codex/memory/*.json` for active memory.
- `scripts/agents/run_end_to_end.py` executes the full loop in one command
  (run generation → metrics attach → prompt build → evaluation).

Quick local smoke test:

```bash
python scripts/agents/codex_generate_patch.py .github/ISSUE_TEMPLATE/feature_request.md
latest_run="$(ls -td .codex/runs/* | head -n1)"
python scripts/agents/append_metrics.py benchmarks/results.sample.json "$latest_run"
python scripts/agents/build_codex_prompt.py "$latest_run/request.json" --run-dir "$latest_run" --out "$latest_run/prompt.json"
python scripts/agents/evaluate_run.py "$latest_run"

# or run all stages:
python scripts/agents/run_end_to_end.py .github/ISSUE_TEMPLATE/feature_request.md --metrics benchmarks/results.sample.json
```

---

## Specs + Docs

**Specifications** (normative):

| Document | Content |
|----------|---------|
| [spec/SPEC.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/SPEC.md) | Normative requirements |
| [spec/STATES.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/STATES.md) | State machine + transitions |
| [spec/JURISDICTION.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/JURISDICTION.md) | Policy rules |
| [spec/AUDIT.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/AUDIT.md) | Ledger + hashing + evidence bundle |
| [spec/ERROR_MODEL.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/ERROR_MODEL.md) | Error taxonomy |
| [spec/VARIANTS.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/VARIANTS.md) | Posture variants |

**Architecture + Threat Model**:

| Document | Content |
|----------|---------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component boundaries and data flows |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversary model + mitigations |
| [docs/pipelines/HPC_CICD_ARCHITECTURE.md](docs/pipelines/HPC_CICD_ARCHITECTURE.md) | Production-grade CI/CD architecture for kernel projects |
| [docs/FAQ.md](docs/FAQ.md) | Usage clarifications |

---

## What This Refuses To Be

| Not This | Because |
|----------|---------|
| LLM wrapper | Doesn't call models |
| Prompt framework | Doesn't "improve" prompts |
| Agent framework | Doesn't define behaviour |
| "Alignment" | Doesn't solve values |
| RBAC | Jurisdiction is execution-boundary enforcement |
| Dashboard | Outputs evidence; visualisation is out of scope |

It does one job: **deterministic arbitration with immutable audit**.

---

## Versioning Policy

SemVer with strict interpretation:

| Version | Meaning |
|---------|---------|
| `0.x.y` | Development; invariants stable; API may change |
| `1.0.0` | Invariants + API surface frozen |

**Breaking change** = any change to invariants, transitions, audit schema, or public types.

---

## Contributing / Security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE)
