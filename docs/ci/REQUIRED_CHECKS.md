# Required status checks for `main`

Status: **proposal, not yet applied.** This file does not change any setting.
Branch protection and rulesets can only be changed in the repository settings
by the repository owner. Applying this list needs a separate settings change
with explicit owner approval.

Source: Shards-kernel production-readiness audit (11 November 2026), quick
win 4: "make the Postgres and secret-scan CI checks required".

## Current state (read on 11 November 2026)

`GET /repos/Shards-foundation/Shards-kernel/branches/main` reports
`protected: true`, with classic branch protection `enabled: false` and
`required_status_checks.contexts: []`. No status check is currently required
by classic branch protection. Any ruleset-level requirements were not read
for this document.

## Checks to make required

GitHub matches required checks by the check-run name, which for GitHub
Actions is the job's `name:` (or the job id when there is no `name:`, with the
matrix value appended in brackets). The names below are copied from the
workflow files and match the check runs reported on `main` at
`d2ea11420ee7ad41c73e607e56aac8797bd826cd`.

| Required check name (exact) | Workflow file | Job id | Why it should block merges |
|---|---|---|---|
| `Cross-host PostgreSQL accounting gate` | `.github/workflows/ci.yml` (workflow `CI`) | `distributed-accounting` | Only gate that runs the shared permit-accounting, distributed execution and authority-audit invariants against a real PostgreSQL 16 service. |
| `Mandatory local E2E release gate` | `.github/workflows/ci.yml` (workflow `CI`) | `e2e` | Strict multi-process end-to-end acceptance gate; the `quality` matrix already `needs:` it. |
| `Secret scanning` | `.github/workflows/security.yml` (workflow `Security`) | `secret-scanning` | Gitleaks over the full history; prevents a credential landing on `main`. |

### Recommended alongside (owner's choice)

| Check name (exact) | Workflow file | Job id | Note |
|---|---|---|---|
| `quality (3.9)` … `quality (3.15)` | `.github/workflows/ci.yml` | `quality` (matrix) | One check per Python version; each must be listed separately. |
| `Dependency and Python security scans` | `.github/workflows/security.yml` | `vulnerability-scans` | pip-audit and Bandit. |
| `CodeQL Analyze` | `.github/workflows/security.yml` | `codeql` | Static security analysis. |

### Do not make required yet

| Check name (exact) | Workflow file | Job id | Reason |
|---|---|---|---|
| `Type check (mypy, advisory)` | `.github/workflows/ci.yml` | `typecheck` | Non-blocking by design while pre-existing mypy findings are paid down. |
| `Lint (Ruff full ruleset, advisory)` | `.github/workflows/ci.yml` | `lint-full` | Non-blocking by design while pre-existing Ruff findings are paid down. |
| `Dependency Review` | `.github/workflows/security.yml` | `dependency-review` | Runs only on `pull_request`; reported as skipped on pushes. |

## How the owner would apply this (not done by any PR)

1. Settings → Rules → Rulesets (or Branches → branch protection for `main`).
2. Enable "Require status checks to pass" and add the three exact names in
   "Checks to make required" above, selecting the GitHub Actions app as the
   source.
3. Optionally enable "Require branches to be up to date before merging".
4. Re-check after any job rename: renaming a job's `name:` silently changes
   the required context and will block every PR until updated.
