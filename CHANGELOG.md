# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- Optional SQLite-backed audit persistence for kernel variants, including commit-before-memory-advance, verified ledger recovery on boot, kernel/variant binding, WAL mode, and FULL synchronous commits.
- Executable demos for minimal request handling, evidence verification, and persistent audit recovery; CI runs them across the supported Python matrix.
- Isolated wheel-install verification, Bandit source scanning, pip-audit dependency scanning, and URL-scheme validation in the HTTP SDK client.

### Changed


### Changed

- The PyPI distribution name is `shards-kernel`. The import package remains `kernels`.
- Replaced the truncated `LICENSE` stub with the SPDX MIT text. Copyright line: `Copyright (c) 2026 Shards Inc Ltd`.

### Security

- `python -m kernels.cli.verify` reads `ledger_entries` and checks internal consistency by delegating to `verify_evidence_bundle`. Replay recomputes each entry hash from the entry content and compares `prev_hash` links and `root_hash`. A missing, empty, or unknown entries key, an empty bundle, malformed JSON, an unknown schema, or the legacy `entries` key is a failure with a non-zero exit. An empty entry list is rejected in the CLI before replay, because `replay_and_verify` reports an empty list as consistent. `root_hash` is stored in the bundle, so a match shows only that the bundle is internally consistent (integrity only).
- Tool execution is fail-closed. A tool call requires a permit whose parameters are the parameters that run, even when no HMAC key is configured. Set `KernelConfig.allow_insecure_unpermitted_execution` to opt out on a non-strict kernel. `StrictKernel` ignores that flag.
- Unknown permit constraints, and the documented but previously unimplemented constraints `max_memory_mb` and `allowed_domains`, are rejected. `require_evidence` now requires a non-empty evidence string.
- An intent audit record is appended before a tool runs. If that append fails, the tool does not run. The outcome record stores the parameters that executed.
- A rejected request does not consume a permit's `max_executions` budget.
- Loading an audit bundle verifies the hash chain. A broken chain halts the kernel and does not install the entries.
- An unexpected exception during request processing moves the kernel to `HALTED`. That halt is recorded on the kernel. `StateMachine.reset()` does not clear it, so a halted kernel does not accept another request.
- Ambiguous requests are always denied. `KernelConfig.fail_closed = False` is not an opt-out.
- The async kernel classes delegate to the synchronous kernels. They do not keep a second state machine. `AsyncDispatcher.dispatch` does not run a tool.

### Changed

- Successful tool execution visits `COMPLETED` before returning to `IDLE`. The lifecycle is BOOTING, IDLE, VALIDATING, ARBITRATING, EXECUTING, AUDITING, COMPLETED, HALTED.
- `KernelConfig.jurisdiction` is the jurisdiction name checked against a permit. It defaults to `"default"`.
- A tool call's `params` and `request.params` must be the same object contents. The kernel binds one canonical copy and checks it again immediately before execution.
- CI runs ruff, tests, and coverage on Python 3.9–3.12. The overall coverage gate is 65%, which this suite meets (measured combined coverage 65.8%: 2365/3482 statements, 477/838 branches). Governance modules must stay at or above 90% branch coverage. Workflows for a PyTorch GPU stack, and the self-heal workflow whose YAML did not parse, are removed.
- The audit ledger remains process-local by default; optional `SQLiteAuditStorage` commits each ledger entry before the in-memory chain advances and verifies persisted history on boot. SQLite is single-host storage, not an independently protected archive.
- `RequestBuilder` and `PolicyBuilder` emit a `KernelRequest` and a `JurisdictionPolicy`. Custom policy callables are rejected. The overall coverage gate is 66%.
- Examples, the HTTP adapters, the SDK client and server, and MCP submit tool calls with a permit bound to the exact parameters. Adapter `halt()` passes a reason. Adapter evidence export returns a mapping.

### Removed

- Removed the GitHub Actions workflows `hpc-matrix`, `gpu-hardware`, `benchmark`, `codex-self-heal`, and `codex-pr-generator`. They do not test this package. `codex-self-heal.yml` did not parse: a Python heredoc at column 0 inside a `run: |` block broke the YAML.

### Added

- Added autonomous Codex contribution scaffold workflows: issue-triggered PR generation and CI failure self-healing issue creation.
- Added `scripts/agents/codex_generate_patch.py` and `scripts/agents/build_codex_prompt.py` for auditable run payload generation and skill-constrained prompt composition.
- Added `scripts/agents/append_metrics.py` and `scripts/agents/evaluate_run.py` to persist benchmark deltas, score runs, and maintain `.codex/meta` leaderboard + `.codex/memory` learning artifacts.
- Added `scripts/agents/run_end_to_end.py` to execute the full autonomous scaffold loop in one command for deterministic local/CI validation.
- Added kernel optimization skill packs under `skills/` (`cuda.md`, `tiling.md`, `memory_coalescing.md`) for structured agent prompt injection.
- Added failure-aware skill packs (`optimization_strategies.md`, `compatibility_rules.md`) used for prompt routing by failure type.
- Added a production-grade HPC CI/CD architecture reference document covering deterministic build strategy, GPU matrix validation, release gating, and scaling guidance.
- Added `scripts/org_repo_review.py` to automate organisation-wide repository cloning, lint/type/test/security execution, and consolidated report generation.
- Added new GitHub Actions workflows for expanded HPC matrix validation, dedicated GPU hardware testing, benchmark regression gating, and docs build verification.
- Added a benchmark regression check utility script with baseline support to enforce latency performance thresholds in CI.
- Added MkDocs configuration to enable strict documentation build checks in CI.
- Added a scheduled dependency health workflow that validates installation integrity, runs `pip check`, audits vulnerabilities with `pip-audit`, and verifies package imports across Python 3.9-3.12.
- Added a weekly dependency canary workflow that upgrades core quality tooling to latest versions and runs lint, type checks, tests, and package build validation.
- Expanded CI workflow to run a Python 3.9-3.12 matrix with linting, format checks, type checking, security scanning, coverage-enforced tests, smoke verification, and package build validation.
- Added dedicated smoke workflow for pull requests and manual dispatch execution.
- Added thread-safe nonce registry reference implementation with TTL cleanup support and observability metrics via `stats()`.
- Added SQLite audit storage reference implementation with append/list operations and service diagnostics through `health()`.
- Added coverage tests for the reference implementations.
- Added developer automation improvements to the Makefile for formatting checks, smoke tests, dependency scanning, and build verification.

### Changed

- Extended the security workflow with dependency review, CodeQL scheduling, vulnerability scans (`safety` and `pip-audit`), and secret scanning using gitleaks.
- Extended smoke script coverage to execute reference implementation runtime checks.
- Updated release workflow to verify distribution metadata with `twine check` before PyPI publishing.

## [0.1.0] - 2026-01-01

### Added

- Added a production-grade HPC CI/CD architecture reference document covering deterministic build strategy, GPU matrix validation, release gating, and scaling guidance.
- Added new GitHub Actions workflows for expanded HPC matrix validation, dedicated GPU hardware testing, benchmark regression gating, and docs build verification.
- Added a benchmark regression check utility script with baseline support to enforce latency performance thresholds in CI.
- Added MkDocs configuration to enable strict documentation build checks in CI.
- Initial kernel implementation with deterministic state machine
- Core types: KernelState, KernelRequest, KernelReceipt, Decision, ReceiptStatus
- Append-only audit ledger with hash-chained entries
- Jurisdiction policy engine with composable rules
- Tool registry with built-in `echo` and `add` tools
- Four kernel variants: strict, permissive, evidence-first, dual-channel
- Replay verification for audit ledger
- CLI entrypoint with help and version commands
- Formal specification pack under `/spec`
- Five working examples demonstrating core functionality
- Complete test suite

### Fixed

- N/A (initial release)

### Changed

- N/A (initial release)

### Removed

- N/A (initial release)

### Security

- Fail-closed semantics enforced by default
- Hash chain integrity verification on replay
- Jurisdiction checks mandatory before execution
