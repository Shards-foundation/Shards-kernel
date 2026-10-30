# Shards-Kernel Repository Structure

**Version:** 0.1.0  
**Last Updated:** January 2025

---

## 1. Overview

This document describes the repository structure, file organization, and module responsibilities.

---

## 2. Directory Tree

```
shards_kernel/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── FUNDING.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── architecture/
│   │   ├── AXIOMS.md
│   │   ├── SCHEMAS.md
│   │   └── STRUCTURE.md
│   ├── compliance/
│   │   ├── CHECKLISTS.md
│   │   └── COMPLIANCE_FRAMEWORK.md
│   ├── pipelines/
│   │   └── GATES.md
│   ├── research/
│   │   └── WHITEPAPER.md
│   ├── roadmap/
│   │   ├── BLUEPRINT.md
│   │   ├── PRD.md
│   │   └── ROADMAP.md
│   ├── security/
│   │   ├── ATTACK_VECTORS.md
│   │   ├── HARDENING.md
│   │   └── SECURITY_AUDIT.md
│   ├── ARCHITECTURE.md
│   ├── FAQ.md
│   ├── README.md
│   └── THREAT_MODEL.md
├── examples/
│   ├── 01_minimal_request.py
│   ├── 02_tool_execution.py
│   ├── 03_fail_closed_ambiguity.py
│   ├── 04_external_audit_replay.py
│   └── 05_variant_comparison.py
├── shards_kernel/
│   ├── audit/
│   │   ├── __init__.py
│   │   ├── ledger.py
│   │   └── replay.py
│   ├── common/
│   │   ├── __init__.py
│   │   ├── codec.py
│   │   ├── errors.py
│   │   ├── hashing.py
│   │   ├── time.py
│   │   ├── types.py
│   │   └── validate.py
│   ├── execution/
│   │   ├── __init__.py
│   │   ├── dispatcher.py
│   │   └── tools.py
│   ├── jurisdiction/
│   │   ├── __init__.py
│   │   ├── policy.py
│   │   └── rules.py
│   ├── state/
│   │   ├── __init__.py
│   │   ├── machine.py
│   │   └── transitions.py
│   ├── variants/
│   │   ├── base.py
│   │   ├── dual_channel_kernel/
│   │   │   ├── __init__.py
│   │   │   └── kernel.py
│   │   ├── evidence_first_kernel/
│   │   │   ├── __init__.py
│   │   │   └── kernel.py
│   │   ├── permissive_kernel/
│   │   │   ├── __init__.py
│   │   │   └── kernel.py
│   │   ├── strict_kernel/
│   │   │   ├── __init__.py
│   │   │   └── kernel.py
│   │   └── __init__.py
│   ├── __init__.py
│   ├── __main__.py
│   ├── _version.py
│   └── api.py
├── scripts/
│   ├── run_tests.sh
│   └── smoke.sh
├── spec/
│   ├── AUDIT.md
│   ├── ERROR_MODEL.md
│   ├── EVIDENCE.md
│   ├── GLOSSARY.md
│   ├── JURISDICTION.md
│   ├── PERMITS.md
│   ├── PLANES.md
│   ├── PROPOSAL.md
│   ├── README.md
│   ├── SPEC.md
│   ├── STATES.md
│   └── VARIANTS.md
├── tests/
│   ├── __init__.py
│   ├── test_audit_ledger.py
│   ├── test_hashing.py
│   ├── test_jurisdiction.py
│   ├── test_replay.py
│   ├── test_state_machine.py
│   └── test_variants.py
├── .gitignore
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
├── README.md
└── SECURITY.md
```

---

## 3. Module Responsibilities

### 3.1 Core Library (`shards_kernel/`)

| Module | Responsibility |
|--------|----------------|
| `api.py` | Public API surface |
| `__init__.py` | Package exports |
| `__main__.py` | CLI entrypoint |
| `_version.py` | Version information |

### 3.2 Common (`shards_kernel/common/`)

| Module | Responsibility |
|--------|----------------|
| `types.py` | Core type definitions |
| `errors.py` | Error classes |
| `hashing.py` | Hash utilities |
| `time.py` | Time utilities |
| `codec.py` | Serialization |
| `validate.py` | Validation functions |

### 3.3 State (`shards_kernel/state/`)

| Module | Responsibility |
|--------|----------------|
| `transitions.py` | Transition definitions |
| `machine.py` | State machine implementation |

### 3.4 Jurisdiction (`shards_kernel/jurisdiction/`)

| Module | Responsibility |
|--------|----------------|
| `policy.py` | Policy definitions |
| `rules.py` | Rule evaluation |

### 3.5 Audit (`shards_kernel/audit/`)

| Module | Responsibility |
|--------|----------------|
| `ledger.py` | Append-only ledger |
| `replay.py` | Replay verification |

### 3.6 Execution (`shards_kernel/execution/`)

| Module | Responsibility |
|--------|----------------|
| `tools.py` | Tool registry |
| `dispatcher.py` | Execution dispatch |

### 3.7 Variants (`shards_kernel/variants/`)

| Module | Responsibility |
|--------|----------------|
| `base.py` | Base kernel protocol |
| `strict_kernel/` | Maximum enforcement |
| `permissive_kernel/` | Relaxed thresholds |
| `evidence_first_kernel/` | Evidence required |
| `dual_channel_kernel/` | Constraints required |

---

## 4. Documentation Structure

### 4.1 Specifications (`spec/`)

| Document | Content |
|----------|---------|
| `SPEC.md` | Core invariants |
| `GLOSSARY.md` | Term definitions |
| `STATES.md` | State machine |
| `JURISDICTION.md` | Policy rules |
| `AUDIT.md` | Ledger schema |
| `ERROR_MODEL.md` | Failure semantics |
| `VARIANTS.md` | Kernel variants |
| `PLANES.md` | Four planes architecture |
| `PROPOSAL.md` | Proposal schema |
| `PERMITS.md` | Permit tokens |
| `EVIDENCE.md` | Evidence packets |

### 4.2 Documentation (`docs/`)

| Directory | Content |
|-----------|---------|
| `architecture/` | Axioms, schemas, structure |
| `compliance/` | Frameworks, checklists |
| `pipelines/` | CI/CD gates |
| `research/` | Whitepaper, insights |
| `roadmap/` | PRD, roadmap, blueprint |
| `security/` | Audit, hardening, vectors |

### 4.3 Root Documents

| Document | Content |
|----------|---------|
| `README.md` | Project overview |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | Contribution guide |
| `SECURITY.md` | Security policy |
| `CODE_OF_CONDUCT.md` | Community standards |
| `LICENSE` | MIT license |

---

## 5. Test Structure

### 5.1 Test Modules

| Module | Coverage |
|--------|----------|
| `test_hashing.py` | Hash utilities |
| `test_state_machine.py` | State machine |
| `test_jurisdiction.py` | Policy evaluation |
| `test_audit_ledger.py` | Ledger operations |
| `test_replay.py` | Replay verification |
| `test_variants.py` | Kernel variants |

### 5.2 Test Categories

| Category | Location |
|----------|----------|
| Unit tests | `tests/test_*.py` |
| Integration tests | `tests/test_*.py` |
| Examples | `examples/*.py` |
| Smoke tests | `scripts/smoke.sh` |

---

## 6. Configuration Files

### 6.1 Python Configuration

| File | Purpose |
|------|---------|
| `pyproject.toml` | Package configuration |

### 6.2 Git Configuration

| File | Purpose |
|------|---------|
| `.gitignore` | Ignored files |

### 6.3 GitHub Configuration

| File | Purpose |
|------|---------|
| `.github/FUNDING.yml` | Sponsorship |
| `.github/ISSUE_TEMPLATE/` | Issue templates |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR template |

---

## 7. Import Graph

```
shards_kernel/
├── api.py
│   ├── common/types.py
│   ├── common/errors.py
│   ├── audit/ledger.py
│   ├── audit/replay.py
│   ├── jurisdiction/policy.py
│   └── variants/
│       ├── strict_kernel/
│       ├── permissive_kernel/
│       ├── evidence_first_kernel/
│       └── dual_channel_kernel/
│
├── variants/base.py
│   ├── common/types.py
│   ├── common/errors.py
│   ├── state/machine.py
│   ├── audit/ledger.py
│   ├── jurisdiction/policy.py
│   └── execution/dispatcher.py
│
├── state/machine.py
│   ├── common/types.py
│   ├── common/errors.py
│   └── state/transitions.py
│
├── audit/ledger.py
│   ├── common/types.py
│   ├── common/hashing.py
│   ├── common/codec.py
│   └── common/time.py
│
├── jurisdiction/policy.py
│   ├── common/types.py
│   └── jurisdiction/rules.py
│
└── execution/dispatcher.py
    ├── common/types.py
    ├── common/errors.py
    └── execution/tools.py
```

---

## 8. Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                         api.py                              │
│                    (Public Surface)                         │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   variants/   │    │    audit/     │    │ jurisdiction/ │
│               │    │               │    │               │
│ StrictKernel  │    │ AuditLedger   │    │ Policy        │
│ Permissive... │    │ replay_verify │    │ Rules         │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                              ▼
                    ┌───────────────┐
                    │    common/    │
                    │               │
                    │ types         │
                    │ errors        │
                    │ hashing       │
                    │ codec         │
                    │ time          │
                    │ validate      │
                    └───────────────┘
                              │
                              ▼
                    ┌───────────────┐
                    │   Python      │
                    │   stdlib      │
                    │               │
                    │ hashlib       │
                    │ dataclasses   │
                    │ enum          │
                    │ typing        │
                    └───────────────┘
```

---

## 9. File Naming Conventions

| Pattern | Usage |
|---------|-------|
| `snake_case.py` | Python modules |
| `UPPER_CASE.md` | Documentation |
| `test_*.py` | Test modules |
| `##_name.py` | Numbered examples |
| `*.sh` | Shell scripts |

---

## 10. Code Statistics

| Metric | Value |
|--------|-------|
| Python files | 33 |
| Lines of code | ~2,900 |
| Test files | 7 |
| Test lines | ~900 |
| Spec documents | 12 |
| Doc documents | 15+ |
| Examples | 5 |
