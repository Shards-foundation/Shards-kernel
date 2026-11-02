# Shards-Kernel production acceptance programme

**Status:** Pre-production. **Scope:** control-plane kernel, not the Shards
MCP Gateway or the agent-dashboard product. **Basis:** `main` as observed
on 2 November 2026, plus independently reviewed open changes.

No evidence may be marked *verified in staging* solely because a unit test,
local demo or CI check passed. All nine areas require **inspectable artifacts**
bound to immutable Git commit SHA, environment identity and test timestamp.

## System boundary

```
Human operator / agents
         |
  Shards MCP Gateway  -- remote protocol, identity, client sessions
         |
  Shards-Kernel       -- deterministic admission, permit/policy, audit
         |
  Trusted tool adapter -- downstream idempotency and reconciliation
         |
  Approved tools only

Dashboard -- read-only projected, redacted state via authenticated API
Observability -- trace/metric exporters OUTSIDE authority decision path
```

The gateway, dashboard, secrets broker and platform infrastructure are
distinct deployments. The kernel is never allowed to inherit broad wallet,
cloud or GitHub permissions merely because an agent possesses them.

## P0 release gates — mandatory before connecting production agents

| Area | Existing evidence | Missing production evidence / acceptance |
|---|---|---|
| Two-agent integration | Two distinct local MCP stdio processes; actor, bearer and Ed25519 permit scope; replay rejection | Separate agent hosts, real nonfinancial reversible tool, identity revocation and signed evidence correlation |
| Remote MCP | Local official MCP v2 stdio relay; restricted mTLS **HTTP** ingress | Standards-compatible MCP remote transport, authenticated client sessions, cert/key lifecycle, network segmentation and hostile ingress testing |
| Durable execution | Single-host SQLite WAL and replay recovery | Atomic distributed permit accounting, external effect idempotency keys, ambiguous outcome journal, restart and provider reconciliation; no automatic retry of uncertain actions |
| Security | Signed policy/permit, constrained agent tools, PRs #85/#86 transport work | Independent approval, protected keys/KMS or equivalent, rotation & revocation drill, identity isolation, signed anti-rollback external checkpoint, hostile-user security assessment |
| Deployment | Installable CLI and loopback operator reference | Tagged image, SBOM/provenance, distinct staging/prod secrets, persistent worker host, repeatable service supervision, controlled upgrade and rollback |
| Operations | Local SQLite restart tests and offline read-only restore rehearsal (this PR) | Encrypted/off-host backups, immutable external root reference, restored process replay proof, RPO/RTO drill, on-call/incident response and actual rollback |
| Release process | Code quality/CI and local E2E PR #88 (not merged as of 2 Nov) | Branch protection + required CI/E2E checks, reviewer independence, recorded go/no-go decision |

**Acceptance rule:** any missing P0 artifact is `NOT_VERIFIED`, not a waived
success. **Trading/wallet signing remains outside this release.**

## P1 operational maturity gates

| Area | Acceptance |
|---|---|
| Observability | OTel context propagation across gateway and kernel; Sentry error capture with redaction; audit root correlation; metrics for requests, denial reason, latency, queue and resource budgets; alert/incident drills |
| Dashboard | Live read-only agent sessions, task status, permit decisions, redacted receipts and evidence verification; no direct administrative bypass; server-authorised tenant views |
| Developer experience | Python and eventual TS contract SDK, versioned JSON schemas/OpenAPI and MCP tool metadata, runnable onboarding, compatibility tests, signed release tag, verified PyPI build/provenance |

P1 user-visible dashboard work can begin during staging development but must
not misrepresent simulated data as live kernel activity.

## Restore drill: current increment

Run in a trusted **single-host operator diagnostic environment**, without
production private signing keys, outside the repository and without deploying
financial connectors:

```bash
python scripts/ops/verify_sqlite_restore.py \
  --source /absolute/private/path/audit.sqlite3 \
  --kernel-id example-kernel \
  --min-entries 2 \
  --expected-root <trusted-64-hex-audit-root> \
  --min-policy-revision 1
```

Replace the placeholders with independently verified non-secret values. A
previously trusted audit root and version floor must come from a protected,
separately administered authority. The script only compares values; it
**cannot authenticate the trustworthiness** of the supplied anchors.

The drill:
1. Rejects non-regular/symlink/relative sources and source inode replacement.
2. Uses SQLite's online backup protocol, including committed WAL records, to
   create a private **temporary** restore copy. Nothing is restored over the
   original database and no write-capable source connection is opened.
3. Performs SQLite full integrity checks, verifies kernel metadata, restores
   the real hash-chained `AuditLedger`, checks a minimum entry count and
   reports the recovered root.
4. Rejects malformed history, root mismatch, insufficient checkpoint revision
   and outstanding `intent` audit events without subsequent `outcome`.
   Such events require operator reconciliation; they do not prove whether a
   downstream external side effect occurred.
5. Returns **bounded, credential-free JSON** and cleans the temporary copy.

The result `LOCAL_RESTORE_VERIFIED` proves *only* a consistent disposable
copy of the local audit ledger. It **does not** create a usable off-host backup,
test live service boot, verify a remote chain anchor, rule out privileged
rollback of the entire local DB, or prove replay-safe external effects. It
must not be represented as satisfying the Operations P0 production gate.

## Release evidence records

Each production gate requires:

- exact commit SHA, image digest, deployed environment name and UTC time;
- operator and independent reviewer identities;
- repeatable test and rollback commands with redacted output;
- passed/failed/blocked status for each invariant, not pass-rate alone;
- logs/traces/receipts with stable correlation IDs and no secret material;
- proof of enforced deployment/branch protections, not policy text alone.

Never merge PR #86 ahead of independent approval and merge of its parent
PR #85. PR #88 is an independent local E2E test gate and must likewise
receive a non-author review. Issue #79 remains the canonical P0 gateway
production acceptance tracker.
