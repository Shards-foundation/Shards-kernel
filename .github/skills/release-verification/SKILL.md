---
name: release-verification
description: Audit Shards-Kernel pull requests, exact-head CI/security checks, independent approvals, agent-facing smoke/E2E evidence and deployment readiness before merge or a local release. Use for security reviews, release gates and handover; never conflate green CI with production certification.
license: MIT
---

# Independent release verification

Use this skill when an agent claims a Shards-Kernel PR or release is ready. It is a **read and verify** procedure. Merely loading the skill does not authorise a merge, GitHub settings change, deployment, tag or publication.

## Exact-head evidence gate

1. Read the PR **current head SHA** and its base branch, then confirm the intended diff is within Shards-Kernel. Don't inspect another Shards repository or reuse its credentials, CI, storage or deployment.
2. Inspect **every** inline review thread and timeline comment; distinguish active blockers, stale resolved findings, and unverified replies. An author's "fixed" comment is not independent verification.
3. Verify the recorded formal `APPROVED` review comes from a **non-author** independent reviewer and matches the **current commit SHA**. An approval on an older commit, a bot `COMMENTED`, or a green mergeability badge cannot substitute.
4. Query GitHub checks and workflow runs **for that exact SHA**, including Python 3.9–3.12, lint, branch-aware coverage, governance coverage, CodeQL, static security, secret scanning, dependency review, docs, smoke and external quality checks that are configured. No failed, pending, cancelled or action-required required checks.
5. Verify branch protection/ruleset enforcement on `main`, including independent review, required checks, conversation resolution and prevention of unauthorised force pushes. An API `403` means **not verified**, not "enabled".
6. Re-check the head SHA and reviews immediately before any approved merge. New commits invalidate old-head sign-off even if GitHub continues to display an approval.

## Code and behaviour requirements

Check that no implementation regresses these security-critical controls:

- Authenticated per-agent identity and **independent signed v2 execution permits**; no self-issued capability or tool/actor spoofing.
- Fail-closed TLS 1.3 mTLS ingress with a 16 KiB aggregate request-header cap, bounded handshakes and capacity recovery.
- Shutdown revocation, in-flight drain and exceptional blocking-start cancellation; no post-stop dispatch.
- Signed policy v2 domain separation, read-only preflight, post-bind checkpoint activation, monotonic local rollback rejection and explicit SQLite handle closure.
- Durable audit replay, replay isolation across restarts and conservative refusal after ambiguous external side effects.
- Strict MCP v2 stdio relay to a **fixed loopback** endpoint. No arbitrary remote MCP, wallets, unrestricted shell or trading tool added through convenience CLI.

The existing code (not this skill) is the enforcement layer. Prefer independent reproduction and negative-path tests to prose assurances. Consult [threat model](../../../docs/THREAT_MODEL.md), [operator preflight](../../../docs/operations/OPERATOR_PREFLIGHT.md), and [official MCP relay](../../../docs/operations/MCP_TWO_AGENT_RELAY.md).

## Run and record tests

From a fresh isolated checkout of the reviewed **SHA** (never assume branch tip has not advanced):

```bash
python -m pip install -e ".[dev,crypto,mcp]"
python -m pytest -q tests/test_mcp_agent_relay.py
python -m pytest -q tests/test_operator_process_restart.py
python -m pytest -q tests/test_separate_issuer_process_e2e.py
```

Where the files exist, include PR #90's `tests/test_mcp_call_cli.py` and `tests/test_mcp_call_e2e.py`; where merged, include the mandatory real-process gate `python scripts/ci/run_e2e_gate.py` from PR #88. **Do not use missing/optional tests as evidence of passing**. The supported CI matrix covers 3.9–3.12, while the official MCP v2 SDK is installed on 3.11+.

The release workflow must not apply a weaker coverage rule than PR CI, and the **unrounded** branch-aware coverage threshold is at least **90%**. Exact test counts change across commits; never reuse an old count as a new result.

## Deployment certification is separate

Even a passing local release candidate is **not production-certified** until independently demonstrated: unique production signing/verification keys, external monotonic audit anchoring, real remote endpoint identity and protection, backup/restore and fault-injection drills, monitoring/alerts, permissioned operational ownership and a protected release lineage. Do not deploy to an existing Render, Railway, Neon, Vercel, Supabase or Sentry project belonging to another Shards service.

## Output contract

Provide a compact matrix per PR with: `head SHA`, `base SHA`, `independent approval SHA`, `unresolved threads`, `current-head checks`, `branch protection`, `merge status`, and links. Mark each `PASS`, `FAIL`, or `NOT VERIFIED`; no speculative green statuses.

Do not merge, self-approve, use `--allow-unsigned-local` in staging, create paid resources, turn on live financial execution or deploy without the relevant explicit authority and all prescribed gates. If an external reviewer or repository administrator is required, explain the blocker rather than bypass it.
