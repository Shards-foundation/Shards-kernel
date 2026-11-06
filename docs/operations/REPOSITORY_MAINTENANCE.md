# Repository maintenance automation

Read-only maintenance checks for Shards-Kernel and other GitHub repositories.
These are **operational observations**, not production certification.

## What is automated

| Command | Coverage | Mutations |
| --- | --- | --- |
| python scripts/maintenance/repo_hygiene.py --repo . | Tracked file encoding, Python syntax, merge markers, line endings, file-size limits | None |
| python scripts/maintenance/workflow_safety.py --repo . | Targeted GitHub Actions unsafe patterns and floating action refs | None |
| python scripts/maintenance/github_actions_watch.py --repo Shards-foundation/Shards-kernel | Recent main-branch workflow failures, stale runs, API coverage completeness | None |

All run with Python 3.9+, standard-library-only code. The hygiene scanner
requires Git installed and the target to be an existing Git worktree.
The workflow scanner requires a repository with .github/workflows.
The Actions monitor uses only the GitHub REST API; public repos need no token.
For private repositories, provide GITHUB_TOKEN through a secret manager or
GitHub Actions token with actions:read. No credentials are committed or logged.

## Local usage

~~~bash
# Validate configuration without filesystem/network access.
python scripts/maintenance/repo_hygiene.py --dry-run
python scripts/maintenance/workflow_safety.py --dry-run
python scripts/maintenance/github_actions_watch.py --dry-run

# Read-only audits on your checkout.
python scripts/maintenance/repo_hygiene.py --repo .
python scripts/maintenance/workflow_safety.py --repo .

# CI health observation, including a hard failure on incomplete pagination.
python scripts/maintenance/github_actions_watch.py \
    --repo Shards-foundation/Shards-kernel \
    --branch main --lookback-hours 168 --stale-minutes 240

# Escalate advisory code hygiene and workflow patterns to a failing exit code.
python scripts/maintenance/repo_hygiene.py --strict
python scripts/maintenance/workflow_safety.py --strict
~~~

The workflow scanner intentionally labels floating action tags such as
github/codeql-action/init@v4 as **advisory**. Six existing floating action
references were observed in main in workflows codeql.yml, security.yml, and
jekyll-gh-pages.yml when this tool was introduced. These must be pinned to
verified full-length hashes in a reviewed separate security PR; this scanner
does not rewrite workflow files or invent trusted hashes.

## Scheduled maintenance

.github/workflows/repository-maintenance.yml provides:
- Static read-only audits for pull requests.
- A scheduled audit on Mondays at 05:37 UTC and manual workflow_dispatch.
- Read-only GitHub token privileges (contents:read, actions:read).
- No automatic release, upgrade, reset, merge, deletion or runtime execution.

If GitHub Actions reports a failure or a run stale beyond the configured
threshold, the observability job exits nonzero, preserving the underlying
failure for a maintainer to investigate. Cancelled, neutral and skipped runs
are logged as advisory; missing/unknown conclusions fail closed. Pagination
incompleteness is an error, not a successful check.

## What could go wrong

- Git is missing, the checkout is malformed, or tracked files have disappeared:
  the hygiene audit fails, never deleting or restoring anything.
- A Python file has newer syntax than the interpreter used for the audit:
  syntax validation may reject it; test against the supported Python matrix.
- GitHub REST rate limits or network timeouts: bounded retries are applied to
  transient problems; incomplete evidence returns a nonzero exit code.
- A workflow is intentionally cancelled: it is reported separately and does
  not hide actual failures.
- Workflow YAML includes dynamically generated actions, anchors, or unusual
  syntax: the scanner is only a heuristic, not a full YAML parser or a
  replacement for CodeQL, Codecov, Codacy, Gitleaks or dependency audits.
- The repository has not had any recent workflow runs: an empty observation
  does **not** prove a healthy CI pipeline. Confirm required check enforcement
  and branch protections independently.

## Legacy review utility warning

The existing scripts/org_repo_review.py is not an appropriate unattended
production maintenance entrypoint. It currently constructs shell commands,
performs hard Git resets or directory removal for existing destinations,
and installs/tests code cloned from organization repositories. Those actions
are unsafe as implicit defaults. Do not run it as a scheduled job until
it has a separate, explicit-safety remediation and independent review.

No new maintenance script invokes that legacy utility.

## Tests

~~~bash
python -m pytest tests/test_repository_maintenance.py -q
~~~

Accept changes only after the existing repository 3.9–3.15 quality matrix,
strict local E2E security gate, PostgreSQL accounting tests and independent
non-author review pass on the exact PR head.
