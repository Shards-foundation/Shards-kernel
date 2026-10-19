# KERNELS - Deterministic Control Planes for AI Systems

[![PyPI version](https://img.shields.io/pypi/v/kernels.svg)](https://pypi.org/project/kernels/)
[![CI](https://github.com/Shards-foundation/kernels/actions/workflows/ci.yml/badge.svg)](https://github.com/Shards-foundation/kernels/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Shards-foundation/kernels/branch/main/graph/badge.svg)](https://codecov.io/gh/Shards-foundation/kernels)

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

KERNELS exists to make those failure modes **structurally expensive** and **forensically obvious**.

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
from kernels import (
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

If a module is not reachable via `kernels.api`, it is **not** a supported API surface.

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

## Install from PyPI

```bash
python -m pip install kernels
```

## Quickstart

```bash
git clone https://github.com/Shards-foundation/kernels.git
cd kernels
python -m pip install -e .
python -m unittest discover -s tests -v
bash scripts/smoke.sh
python examples/01_minimal_request.py
python -m kernels --help
```

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

This repository now includes a drop-in automation scaffold for closed-loop kernel
contributions:

- `.github/workflows/codex-pr-generator.yml` captures issue context (when the
  issue has a `codex` label), prepares a constrained prompt payload, and opens a
  tracking PR containing run artifacts.
- `.github/workflows/codex-self-heal.yml` watches failed CI/benchmark runs and
  opens a `self-heal` issue with structured failure context plus failure
  taxonomy (`failure_type`, `repair_strategy`).
- `scripts/agents/codex_generate_patch.py` writes auditable run payloads to
  `.codex/runs/`.
- `scripts/agents/build_codex_prompt.py` injects kernel skill constraints from
  `/skills` into an agent-ready prompt payload with failure-aware routing.
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
| [spec/SPEC.md](https://github.com/Shards-foundation/kernels/blob/main/spec/SPEC.md) | Normative requirements |
| [spec/STATES.md](https://github.com/Shards-foundation/kernels/blob/main/spec/STATES.md) | State machine + transitions |
| [spec/JURISDICTION.md](https://github.com/Shards-foundation/kernels/blob/main/spec/JURISDICTION.md) | Policy rules |
| [spec/AUDIT.md](https://github.com/Shards-foundation/kernels/blob/main/spec/AUDIT.md) | Ledger + hashing + evidence bundle |
| [spec/ERROR_MODEL.md](https://github.com/Shards-foundation/kernels/blob/main/spec/ERROR_MODEL.md) | Error taxonomy |
| [spec/VARIANTS.md](https://github.com/Shards-foundation/kernels/blob/main/spec/VARIANTS.md) | Posture variants |

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
