# Shards-Kernel local E2E release gate

Status: **pre-production local acceptance**, not a deployed gateway certification.

## Run

On **Linux / Python 3.11+** with ephemeral test credentials:

```bash
python -m pip install -e ".[dev,crypto,mcp]"
python scripts/ci/run_e2e_gate.py
```

The runner lists explicit pytest node IDs, requires **all four scenarios to be
collected and pass**, and fails on skips, xfails, failed assertions or missing
tests. Its exit status is not inferred from total passing unit-test count.
The runner also writes `e2e-results.xml` (local test evidence, not a signed
production evidence bundle). Do not modify the pinned scenario list without
reviewing the release gate.

CI runs this suite in `.github/workflows/ci.yml` on Ubuntu 24.04 / Python
3.12 before the normal quality matrix. This is a dependency inside CI, not
proof that repository branch protection requires the CI check: configure
protected-main rules separately and verify enforcement.

## Scenarios and evidence boundaries

| Scenario | Processes / transport | Assertions |
| --- | --- | --- |
| Independent approval, permit issuance and operator | Spawned interpreters + loopback HTTP | No unapproved permit; signed execution; evidence root survives restart; replay denied |
| Two scoped local MCP agents | Signed operator process + two separate MCP stdio relay clients | Tool discovery, independent credentials, allowlists, tamper/borrow denial, replay after restart |
| Concurrent scoped MCP agents | Signed operator process + two independent MCP stdio relay clients | Simultaneous authorised actions, isolated results, replay and cross-agent denial |
| TLS ingress boundary | Real TLS 1.3 socket, locally hosted operator + ingress | Certificate authentication, pinning, bearer binding, permit enforcement, replay and privileged-path refusal |

**Limitations:** The TLS case uses real sockets but runs the ingress and
operator servers in one test interpreter. The stdio tests use separate OS
processes on **one host**. This does not test Internet routing, independently
deployed hosts, OAuth/OIDC, a remote native MCP Streamable HTTP service, real
KMS/HSM trust, network DDoS resilience, external audit anchors, replica-safe
replay, transaction reconciliation, wallets or financial operations.

The existing full test suite and coverage matrix remain required. This gate
is intentionally smaller and may not replace them.

## Negative-path verification (Codacy review of PR #88)

`tests/test_e2e_gate.py` is included in the standard Python-version CI matrix,
and the release runner is included in branch-aware coverage **only on
supported Python 3.11+** (`--cov=scripts.ci.run_e2e_gate`). Python 3.9/3.10
still run the library-quality matrix but cannot exercise the subprocess E2E
runner. An independent `python -m coverage report --fail-under=90` CI step
rejects below-threshold totals even if the pytest step incorrectly reports
success. The tests launch isolated new Python
interpreters with temporary, **synthetic** pytest scenarios to prove:

- A real scenario passes, while a missing test, skip, expected failure,
  unexpected pass under xfail, or ordinary assertion failure returns nonzero.
- Linux / Python 3.11+ eligibility is enforced; unsupported host/runtime
  exits before Pytest runs.
- The runner's collection and reporting hooks reject missing or deselected
  cases and do not count non-call or expected-failure reports as passes.
- A static CI-graph contract asserts `quality` depends on `e2e`, and refuses
  common bypass configurations (`continue-on-error: true` and
  `if: always()`). This contract test **does not itself prove GitHub's
  actual scheduler skips quality** on a failed upstream run; that must be
  confirmed by a controlled failing CI run, and required-status checks in
  branch protection must be independently configured.

No generated E2E JUnit output or synthetic credentials are production
evidence. The negative-path probes never modify the production scenario
allowlist on disk.

## Separate acceptance gates still needed before production

1. **Deployed staging:** actual external ingress and kernel processes on
   separate hosts, isolated service accounts, injected secrets and network
   segmentation; only bounded allowlisted test tools.
2. **Remote native MCP:** protocol-level authentication and workload
   identity end to end, including revoked certificates and keys.
3. **Crash / recovery:** forced process termination during authorisation,
   dispatch and post-dispatch audit; prove at-most-once semantics or safe
   reconciliation for externally visible effects.
4. **Tamper / rollback:** signed policy downgrade, ledger corruption, lost
   checkpoints, backup restoration, and failure to start until repaired.
5. **Operations:** SLOs, throughput and latency under constrained
   concurrency, monitored failure injection, rollback exercise and incident
   drill.
6. **Financial execution (separate release):** key custody, deterministic
   risk limits, signing isolation, reconciliation and a no-live-funds
   dry-run before any capital can be used.

**Production gate remains CLOSED** until the deployed staging evidence and
independent security sign-off exist. A green local E2E workflow is not a
production authorisation.
