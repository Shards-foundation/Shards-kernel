# Safe organisation-wide repository inventory

This replaces the previous `scripts/org_repo_review.py` implementation, which
cloned repositories, ran repository-controlled tools, used `git reset --hard`,
and deleted workspaces during normal execution. The replacement performs
**read-only HTTPS GET requests to GitHub's REST API**. It does not clone, run,
alter, reset or delete repositories, or create or overwrite report files.

The script requires Python 3.9+ and the standard library only. It is
cross-platform and does not require Git, Docker or a cloud CLI.

## Usage

```bash
python scripts/org_repo_review.py --org Shards-foundation --dry-run
python scripts/org_repo_review.py --org Shards-foundation --format json
python scripts/org_repo_review.py --org Shards-foundation --format markdown
python scripts/org_repo_review.py --org Shards-foundation --check-branches --strict
```

Inject `GITHUB_TOKEN` or `GH_TOKEN` as a read-only
environment secret for access to private repositories. Never supply a token
through arguments, source control or prompts. Without authentication, the
inventory only includes repositories visible anonymously and is not an
authoritative inventory of the organisation.

Report content is printed to stdout, JSON structured operational logs to stderr.
For example, `python scripts/org_repo_review.py --org Shards-foundation --format json > org-review.json`
writes a report through **operator-controlled shell redirection**.
Shell redirection can truncate an existing file; use a separate atomic report
writer where durable archival is required. The script itself never writes files.

Legacy `--workspace` and `--output` flags are intentionally
rejected rather than performing the former destructive operations.

## Evidence and failure semantics

| Exit code | Meaning |
| --- | --- |
| 0 | All visible repos in the requested scope observed; non-strict advisories may remain |
| 1 | Strict advisory violation, or explicit default branch reported unprotected |
| 2 | Invalid input, API failure, pagination incomplete, repository cap reached, no visible repos, or required branch data unverifiable |
| 130 or 143 | SIGINT or SIGTERM interruption |

The maximum pages and response sizes are bounded. A full page at the
pagination limit is not assumed complete. `--repo-limit` may
produce a partial report with `assessment=PARTIAL` and exit 2.
Concurrent changes during pagination can still produce an inconsistent
snapshot; consult GitHub enterprise exports for authoritative reconciliation.

`--check-branches` reports GitHub's `protected` metadata as
`REPORTED_TRUE`, `REPORTED_FALSE` or `NOT_VERIFIED`.
This flag is not independent verification of required checks, administrative
bypass protections or branch rule implementation. Unknown values return exit 2;
an explicitly unprotected default branch returns exit 1. Archived or disabled
repositories are treated separately from active services.

## Failure containment

- **API outages, 429 and 5xx**: bounded exponential retries and network timeouts,
  with nonzero failure when evidence is incomplete.
- **401/403 credentials or permissions**: immediate rejection, no token in
  logs and no redirects carrying credentials.
- **Untrusted repository names/URLs**: validate identity and GitHub names,
  allowlist report fields, ignore clone URLs and never execute remote data.
- **Large organisations**: strict pagination bounds, duplicate-name rejection,
  response size caps and no silent truncation.
- **Stale repositories**: last push is an advisory heuristic, not proof of
  vulnerability, abandonment or ongoing support.

## Tests

```bash
python -m pytest tests/test_org_repo_review.py -q
```

Negative-path tests cover injection attempts, malicious clone URLs,
credentials, network retries, invalid pagination, branch protection unknowns,
empty results, dry-run, removed legacy mutation options and Markdown output.

## Measured branch coverage gate

`.github/workflows/org-inventory-quality.yml` now runs the inventory's
negative-path regression tests on Python 3.12, records branch-aware
coverage and fails if the unrounded result falls below **95%**.
It archives the `coverage-org-inventory.json` report for 14 days.

Before enabling the 95% floor, the expanded suite passed 44 tests
and 32 subtests with 98% branch-aware coverage (rounded) in GitHub CI.
Coverage is a scope-specific quality metric, not evidence of actual
branch-protection enforcement, availability of private repositories, or
production readiness of Shards-Kernel itself.

The existing Python 3.9–3.15 quality matrix, strict real-process E2E gate,
PostgreSQL accounting checks and independent exact-head approval remain
mandatory before merging.
