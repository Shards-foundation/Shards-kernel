# Bounded GitHub issue-label operator

Status: **operator-side production path implemented and tested**. Remote
Cloudflare Edge federation and Tunnel ingress configuration are **not** part of
this change and remain a deployment blocker. References: #118, #115, #116.

This profile adds exactly one trusted provider action to the strict kernel:

```text
github.issue.add_label(issue_number: int, label: str)
```

The provider can only add one allowlisted label to a pre-existing issue in one
operator-pinned repository. It cannot delete labels, merge pull requests,
create issues, call arbitrary URLs, run shell commands or use client-supplied
credentials.

## What is and is not shipped

| Capability | State |
| --- | --- |
| Strict signed v2 permit -> kernel -> provider path | Implemented |
| Durable SQLite provider-effect journal | Implemented |
| Authoritative GitHub read-back verification | Implemented |
| Gateway identity/token validation and header-spoof rejection | Implemented |
| Loopback-only operator listener | Implemented |
| systemd hardening unit and config template | Included, not executed on ARM64 |
| Live GitHub read-back acceptance test | Included, gated and skipped without secrets |
| Cloudflare Worker/Edge federation | **Not implemented — hard blocker** |
| Cloudflare Tunnel/Access ingress configuration | **Not implemented — hard blocker** |
| Automatic retry, label removal, merge, delete | Deliberately not offered |

The deployed Shards-MCP Edge is a separate product. This change does not read,
modify or deploy it. The Edge must eventually authenticate to this operator
through an independently authenticated gateway contract; that contract is
defined below but the Edge side is not implemented here.

## Trust boundaries

```text
Cloudflare Tunnel / authenticated reverse proxy
        |  X-Shards-Gateway-Identity + X-Shards-Gateway-Token
        v
127.0.0.1:8765  Shards-Kernel operator (this service)
        |  agent bearer credential -> actor from credential prefix
        |  exact Ed25519 v2 permit -> signature, audience, params, nonce
        v
strict kernel -> signed intent + outcome audit -> provider journal
        |  operator-held GitHub token from environment
        v
https://api.github.com  POST label, then GET label read-back
```

- The **human approver**, **offline permit issuer**, **operator policy
  signer**, **operator runtime**, **gateway** and **agent** are separate
  identities. An agent can request an action but cannot sign its own permit.
- The agent supplies a bearer credential. Its actor is derived from the
  credential prefix and must match the signed permit `subject`; the JSON
  `actor` field is only cross-checked, never trusted on its own.
- The operator injects `X-Shards-Gateway-Identity` and
  `X-Shards-Gateway-Token`. The service refuses every caller-identity header
  (`X-Actor`, `X-Shards-Actor`, `X-User`, `X-Auth-Request-User`,
  `X-Authenticated-User`, `X-Forwarded-User`, `X-Remote-User`,
  `X-MS-Client-Principal`) entirely.
- The GitHub token is read from an operator-managed environment variable at
  startup and request time. It is never accepted from an agent, written to
  JSON, returned in a receipt or logged by the provider.
- The service binds `127.0.0.1` only. It is not a public listener.

## Operator v3 configuration

`version: 3` is an explicit opt-in profile. Versions 1 and 2 remain
builtin-only and cannot name the provider tool.

```json
{
  "version": 3,
  "kernel_id": "github-issue-label-operator",
  "tools": ["github.issue.add_label", "echo"],
  "agents": [
    {
      "actor": "agent-requester",
      "token_scrypt": "<64 lowercase hex>",
      "allowed_tools": ["github.issue.add_label"]
    },
    {
      "actor": "agent-auditor",
      "token_scrypt": "<64 lowercase hex>",
      "allowed_tools": ["echo"]
    }
  ],
  "issuer_keys": [
    {
      "key_id": "operator-policy-key-1",
      "issuer": "offline-operator-issuer",
      "public_key_hex": "<64 lowercase hex public key>",
      "revoked": false
    }
  ],
  "audit_db": "/var/lib/shards-kernel/github-operator/audit.sqlite3",
  "port": 8765,
  "provider": {
    "kind": "github_issue_label",
    "owner": "your-org",
    "repo": "your-repository",
    "allowed_labels": ["shards-agent"],
    "max_issue_number": 100000,
    "journal_db": "/var/lib/shards-kernel/github-operator/provider-journal.sqlite3",
    "token_env": "SHARDS_KERNEL_GITHUB_TOKEN"
  },
  "gateway": {
    "identity": "cloudflare-tunnel-prod",
    "token_env": "SHARDS_KERNEL_GATEWAY_TOKEN"
  }
}
```

The repository contains a full template at
`deploy/github-operator.config.example.json`. It contains no secrets, but its
`REPLACE_WITH_*` agent verifier and issuer-key placeholders deliberately fail
parsing until the operator replaces them. The v3
profile **requires** `gateway`; a v3 document without it is rejected.

Validation rules include:

- `owner`/`repo` are concrete GitHub names; no URLs, globs or path traversal.
- `allowed_labels` is a unique nonempty list of at most 32 exact names.
- `max_issue_number` is an integer between 1 and 10,000,000.
- `journal_db` and `audit_db` are absolute paths whose parent exists; symlinks
  and directories are refused.
- `provider.token_env` must use the `SHARDS_KERNEL_GITHUB_` namespace and
  `gateway.token_env` must use `SHARDS_KERNEL_GATEWAY_`; cross-role aliases are
  rejected so the two credentials cannot be swapped by configuration.
- `token_env` names an uppercase environment variable and cannot reuse the
  operator admin, agent pepper or policy key variable.
- Gateway and provider credentials must use different environment variables
  and different values.
- The provider tool must be present in `tools`, and each agent's tool scope
  cannot exceed `tools`.
- No wildcard actor or tool is accepted.

Sign the configuration with the separate offline issuer. The operator service
never holds the policy private key:

```python
from shards_kernel.issuer import sign_operator_policy

policy = sign_operator_policy(
    config,
    signing_key,          # Ed25519PrivateKey, offline issuer only
    revision=1,
    issued_at_ms=now_ms,
    expires_at_ms=now_ms + 24 * 60 * 60 * 1000,
)
```

Install the signed envelope as
`/etc/shards-kernel/github-operator.signed.json`. The operator verifies it with
`SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX` from its environment.

## Reverse proxy / Tunnel contract

The operator is loopback-only. A trusted local reverse proxy or Cloudflare
Tunnel must:

1. Terminate client TLS and authenticate the caller outside this service.
2. Forward only to `http://127.0.0.1:8765`.
3. Remove any client-supplied `X-Shards-Gateway-Identity`,
   `X-Shards-Gateway-Token` and caller-identity headers (`X-Actor`,
   `X-Shards-Actor`, `X-User`, `X-Auth-Request-User`, `X-Authenticated-User`,
   `X-Forwarded-User`, `X-Remote-User`, `X-MS-Client-Principal`).
4. Inject the operator-configured gateway identity and gateway token.
5. Preserve the agent `Authorization: Bearer ...` header unchanged.

The service fails closed when the gateway token is absent, wrong, too short,
equal to the provider token, or when the identity does not match the signed
operator configuration. It also fails closed when a forbidden actor header is
present. This is a shared-secret gateway contract, not mTLS and not a
replacement for the separate mTLS ingress runbook.

Do not configure a public listener on the operator host. Do not modify the
existing Cloudflare Edge as part of this profile.

## Permit and request shape

The issuer signs an exact Ed25519 v2 permit with:

- `audience` equal to the operator `kernel_id`;
- `subject` equal to the authenticated agent actor;
- `action` equal to `github.issue.add_label`;
- `params` equal to `{"issue_number": <int>, "label": "<allowlisted>"}`;
- `max_executions: 1`;
- a bounded validity window.

The agent submits:

```json
{
  "request_id": "<unique>",
  "actor": "agent-requester",
  "intent": "add one allowlisted label",
  "tool_call": {
    "name": "github.issue.add_label",
    "params": {"issue_number": 123, "label": "shards-agent"}
  },
  "params": {"issue_number": 123, "label": "shards-agent"},
  "permit": { "...": "signed v2 permit mapping" }
}
```

The kernel rejects a forged signature, wrong audience, expired or
not-yet-valid permit, params mismatch, tool/actor mismatch, replay, unknown
tool, wildcard policy and unavailable audit storage. A denied request produces
no provider call.

## Effect semantics

The provider journals every operation before dispatch. It never retries a
possibly applied write automatically.

| Observation | Journal state | Effect |
| --- | --- | --- |
| Label already present before POST | `SUCCEEDED` | No POST; `already_present=true` |
| POST 200/201 and read-back shows label | `SUCCEEDED` | Verified |
| POST 404/410/422 and read-back shows label absent | `NOT_APPLIED` | Definitive rejection |
| POST 403/429/5xx, timeout, dropped connection | `UNKNOWN` | Quarantined; no retry |
| Read-back unavailable after dispatch | `UNKNOWN` | Quarantined; no retry |
| Preflight issue missing (404) | `NOT_APPLIED` | No POST |
| Preflight read-back unavailable | `NOT_APPLIED` | No POST; new signed permit required |
| Restart with `DISPATCHED`/`UNKNOWN` record | read-back only | `SUCCEEDED` only if label visible, otherwise `UNKNOWN` |

The journal `provider_ref` is a bounded, printable-ASCII evidence string. It
keeps the readable `github:<owner>/<repo>#<issue>:<label>` form when that value
is at most 200 characters and ASCII. A Unicode or over-long label is stored as
`github:sha256:<64 hex>`, a SHA-256 digest over the exact
provider/owner/repo/issue/label tuple. The digest is deterministic and never
truncates or aliases two different effects. The journal's `params_sha256` is
still the authoritative parameter binding. GitHub label names are not otherwise
restricted to ASCII by this adapter.

This is **not** an exactly-once side-effect guarantee. If a request ends
`UNKNOWN`, a human must inspect the issue. A new action requires a new signed
permit and a new request id; the same permit is denied as a replay. The
provider's preflight read-back prevents a new authorised request from adding a
label that is already present.

Label addition is reversible only by a separately authorised human in GitHub.
The provider offers no delete, remove, merge or close operation.

## Incident runbook: journal `SUCCEEDED` with no audit outcome

A provider effect can be applied and durably journalled as `SUCCEEDED`, then
the kernel's hash-chained **outcome** audit append can fail. The kernel then
HALTs and returns HTTP 500. The audit chain holds the `intent` and `halt`
records but **no outcome** for that request. This is fail-closed for new
admissions, but it is not complete evidence that the effect was authorised and
completed end-to-end.

**Never treat a journal `SUCCEEDED` row as proof of a complete governed
action.** A journal row records what the provider adapter did. Only a matching
hash-chained `outcome` record plus external ground truth proves the governed
result.

### 1. Freeze and keep HALTED

- Do not restart the service, clear the halt, issue new permits, or retry the
  provider call.
- If the process is still running, confirm the kernel state is `HALTED` and
  leave it there. If the process exited, keep the systemd unit stopped.
- New admissions must remain denied until this runbook completes and an
  authorised operator approves recovery.

### 2. Preserve same-snapshot evidence

Capture both SQLite databases from the **same instant**, plus the signed
policy and unit/environment metadata (never the secret values):

```bash
sudo systemctl stop shards-kernel-github-operator.service
sudo install -d -o root -g root -m 0700 /var/lib/shards-kernel/incident-<id>
sudo sqlite3 /var/lib/shards-kernel/github-operator/audit.sqlite3 \
  ".backup '/var/lib/shards-kernel/incident-<id>/audit.sqlite3'"
sudo sqlite3 /var/lib/shards-kernel/github-operator/provider-journal.sqlite3 \
  ".backup '/var/lib/shards-kernel/incident-<id>/provider-journal.sqlite3'"
sudo cp /etc/shards-kernel/github-operator.signed.json \
  /var/lib/shards-kernel/incident-<id>/
sudo chmod 0400 /var/lib/shards-kernel/incident-<id>/*
```

The directory is **root-owned and root-only**. Record `sha256sum`, inode,
size and mtime of every preserved file. Do not edit, repair or re-sign
either database.

The reconciler must run as an unprivileged account, so it cannot read that
root-only snapshot directly. Make a disposable working copy owned by the
service account and leave the preserved snapshot untouched:

```bash
sudo -u shards-kernel install -d -m 0700 \
  /var/lib/shards-kernel/github-operator/reconcile-<id>
sudo cp \
  /var/lib/shards-kernel/incident-<id>/audit.sqlite3 \
  /var/lib/shards-kernel/incident-<id>/provider-journal.sqlite3 \
  /var/lib/shards-kernel/github-operator/reconcile-<id>/
sudo chown shards-kernel:shards-kernel \
  /var/lib/shards-kernel/github-operator/reconcile-<id>/*.sqlite3
sudo chmod 0600 \
  /var/lib/shards-kernel/github-operator/reconcile-<id>/*.sqlite3
```

Confirm the working copy is byte-identical to the preserved snapshot before
running anything:

```bash
sudo sha256sum /var/lib/shards-kernel/incident-<id>/*.sqlite3
sudo -u shards-kernel sha256sum \
  /var/lib/shards-kernel/github-operator/reconcile-<id>/*.sqlite3
```

The working directory is writable by the service account so SQLite can create
its read-only `-shm`/`-wal` side files there. The preserved snapshot stays
private and immutable.

### 3. Establish external ground truth, read-only

Using a separate human credential (never the agent bearer or the kernel
journal), read the label state for the exact configured owner/repository and
issue. Record the observation time, the actor, the API response and whether
the label is present. Do not add or remove a label during triage.

If the issue, repository or owner does not match the operator configuration,
stop and treat it as a separate scope incident.

### 4. Correlate journal and audit, read-only

Run the read-only reconciliation tool as the unprivileged service account
against the working copy:

```bash
sudo -u shards-kernel /opt/shards-kernel/.venv/bin/python \
  /opt/shards-kernel/scripts/ops/reconcile_provider_effects.py \
  --audit-db /var/lib/shards-kernel/github-operator/reconcile-<id>/audit.sqlite3 \
  --journal-db /var/lib/shards-kernel/github-operator/reconcile-<id>/provider-journal.sqlite3
```

It opens both files with `mode=ro` and `PRAGMA query_only`, verifies the audit
hash chain, re-derives the operation id from `request_id`, `permit_id` and
`params_sha256`, and never writes, retries or fabricates a record.

Exit codes are snapshot-wide: `0` clean, `2` any incident **or** attention,
`1` tool error. A clean new operation does not turn the process exit code into
`0` while an older incident is still present. Read the per-record
classifications, not only the exit status.

| Classification | Meaning |
| --- | --- |
| `COMPLETE_SUCCEEDED` | Journal `SUCCEEDED` and matching `ALLOW` outcome audit |
| `COMPLETE_NOT_APPLIED` | Journal `NOT_APPLIED` and matching `DENY` outcome audit |
| `INCIDENT_EFFECT_APPLIED_NO_OUTCOME` | **This runbook.** Journal `SUCCEEDED`, intent present, outcome absent |
| `INCIDENT_NOT_APPLIED_NO_OUTCOME` | Journal `NOT_APPLIED`, intent present, outcome absent |
| `INCIDENT_OUTCOME_MISMATCH` | Outcome exists but its decision contradicts the journal |
| `INCIDENT_INTENT_MISSING` | Journal terminal state with no matching audit intent |
| `INCIDENT_JOURNAL_RECORD_MISSING` | Audit intent with no journal row and no proof of a pre-dispatch denial (lost or mismatched journal) |
| `PREDISPATCH_DENIED` | Audit intent followed by a kernel-generated denial before provider dispatch (for example `REPLAY_DETECTED`, an expired authorisation deadline or a denying runtime hook); no provider effect, but still requires attention |
| `QUARANTINED_UNKNOWN` | Ambiguous provider effect; human read-back required |
| `OPEN_OPERATION` | `INTENT`/`DISPATCHED`; never retry automatically |
| `BINDING_MISMATCH` | Re-derived operation id or provider/action binding disagrees |

An illustrative SQL check is shown below. Every join alias is explicit. A
previous review sample used `e.request_id = request_id`; an unqualified
right-hand side resolves to the inner table column and becomes the tautology
`e.request_id = e.request_id`, hiding exactly the missing-outcome row. Never
use an unqualified column on either side of this join.

```sql
-- Illustrative only; the Python tool above is the authoritative procedure.
SELECT j.operation_id, j.request_id, j.permit_id, j.state
FROM provider_effect_journal AS j
LEFT JOIN audit_entries AS i
  ON i.kernel_id = :kernel_id
 AND i.request_id = j.request_id
 AND json_extract(i.payload_json, '$.audit_phase') = 'intent'
 AND json_extract(i.payload_json, '$.permit_digest') = j.permit_id
 AND json_extract(i.payload_json, '$.params_hash') = j.params_sha256
LEFT JOIN audit_entries AS o
  ON o.kernel_id = :kernel_id
 AND o.request_id = j.request_id
 AND json_extract(o.payload_json, '$.audit_phase') = 'outcome'
 AND json_extract(o.payload_json, '$.permit_digest') = j.permit_id
 AND json_extract(o.payload_json, '$.params_hash') = j.params_sha256
WHERE j.state = 'SUCCEEDED' AND o.entry_hash IS NULL;
```

### 5. Record the incident outside the signed chain

Create an incident record in the operator's external system (ticket, change
log, or signed incident register) containing:

- `request_id`, `operation_id`, `permit_id`, owner/repository/issue and label;
- journal state, `provider_ref` and sanitized detail;
- audit `intent` and `halt` `entry_hash` values and `ledger_seq`;
- the external label observation and its source;
- the operator decision, approver identity and timestamp.

Do **not** insert a synthetic outcome, edit the journal state, add a hash-chain
entry, or re-sign the ledger. The discrepancy is the evidence. A restore drill
(`scripts/ops/verify_sqlite_restore.py`) will report
`UNRECONCILED_EXECUTION_INTENTS` for this database; that is the expected
result and must be recorded as an accepted external exception, not "fixed" by
editing the database.

### 6. Restart and replay protection (only after approval)

The kernel's `HALTED` state is in memory. A process restart boots `IDLE` from
the restored audit chain and does **not** enforce this reconciliation. Safe
restart is therefore an operator procedure, not a code guarantee: treat it as
a **remaining blocker** for automatic recovery.

After the incident record is accepted:

- do not reuse the original permit, nonce or `request_id`; the restored
  `intent` consumes the nonce and must be denied as `REPLAY_DETECTED`;
- issue a new signed v2 permit (new `permit_id`/nonce) and a new `request_id`;
- if the label is already present, the provider preflight must return
  `SUCCEEDED` with `already_present=true` and **zero** POST requests;
- if the preflight would POST, stop and re-triage;
- if a human removed the label and a new action is desired, that is a new
  authorised action under its own permit, not recovery of the old operation.

### 7. True recovery acceptance

Recovery is complete only when all of these are observed and recorded:

1. The preserved audit chain verifies (`replay_and_verify` / restore drill).
2. Reconciliation reports `COMPLETE_SUCCEEDED` for the new operation and
   still reports the old operation as the accepted external exception. The
   command still exits `2` for the snapshot while that old incident remains;
   there is no per-record exit code and no whole-snapshot exit `0` claim.
   Acceptance is the per-record classification plus the recorded external
   exception, not a zero exit status.
3. `/health` is healthy and `/status` shows `IDLE` with gateway auth enforced.
4. Replaying the original permit returns `REPLAY_DETECTED` and the provider
   POST count does not increase.
5. A new signed permit returns `ALLOW` with `already_present=true` and no POST.
6. External label state matches the incident record.
7. Evidence hashes, tool output and preserved snapshots are archived.

### 8. Limits of this recovery

- The tool correlates two local SQLite files. It does not call GitHub, prove a
  remote label state, repair the chain, or restore a missing outcome.
- It cannot distinguish a label added by this operation from a label added by
  another actor at the same time; use external provider audit logs.
- Read-only WAL access may create `-shm`/`-wal` side files in the directory.
  Run against the writable working copy described in step 2, never against the
  root-only preserved snapshot.
- Single-host only. There is no HA, distributed locking or cross-host
  reconciliation.
- The effect is not exactly-once. Do not claim complete effect evidence in
  this failure envelope.
- This runbook does not authorise a merge, deployment, release, token change
  or branch-protection change.

## Install on Ubuntu/Debian ARM64

The unit targets a native ARM64 Python environment. Validate it on the target
host; this repository's test environment is Linux x86_64.

```bash
sudo useradd --system --home /opt/shards-kernel --shell /usr/sbin/nologin shards-kernel
sudo install -d -o shards-kernel -g shards-kernel -m 0750 /opt/shards-kernel
sudo install -d -o root -g shards-kernel -m 0750 /etc/shards-kernel
sudo install -d -o shards-kernel -g shards-kernel -m 0700 /var/lib/shards-kernel/github-operator

# Install the release into /opt/shards-kernel/.venv (see release verification).
sudo -u shards-kernel /opt/shards-kernel/.venv/bin/python -m shards_kernel doctor --profile service

sudo install -o root -g shards-kernel -m 0640 \
  deploy/systemd/github-operator.env.example /etc/shards-kernel/github-operator.env
sudo editor /etc/shards-kernel/github-operator.env   # fill values; never commit

sudo install -o root -g shards-kernel -m 0640 \
  /path/to/github-operator.signed.json /etc/shards-kernel/github-operator.signed.json
sudo install -o root -g root -m 0644 \
  deploy/systemd/shards-kernel-github-operator.service \
  /etc/systemd/system/shards-kernel-github-operator.service

sudo systemctl daemon-reload
sudo systemctl enable --now shards-kernel-github-operator.service
sudo systemctl status shards-kernel-github-operator.service
```

The unit uses `ProtectSystem=strict`, an empty capability set,
`NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `PrivateUsers`, a system-call
filter, a read-only application tree and a single writable state directory.
It does not grant network binding privileges; port 8765 is unprivileged.

Local checks:

```bash
curl -fsS http://127.0.0.1:8765/health
curl -fsS -H "X-Shards-Gateway-Identity: cloudflare-tunnel-prod" \
  -H "X-Shards-Gateway-Token: $SHARDS_KERNEL_GATEWAY_TOKEN" \
  -H "Authorization: Bearer $SHARDS_KERNEL_API_KEY" \
  http://127.0.0.1:8765/status
```

## Backup, recovery and rollback

Back up, as one consistent set:

- `audit.sqlite3` (replay ledger, signed-policy checkpoint, intent/outcome
  chain);
- `provider-journal.sqlite3` (durable effect intent, dispatch and outcome);
- the signed operator policy envelope;
- the systemd unit and the environment file (store the secret file encrypted
  offline, never in the repository).

Stop the service before copying SQLite files, or use SQLite's online backup
mechanism:

```bash
sudo systemctl stop shards-kernel-github-operator.service
sudo install -d -m 0700 /var/backups/shards-kernel
sudo sqlite3 /var/lib/shards-kernel/github-operator/audit.sqlite3 \
  ".backup '/var/backups/shards-kernel/audit.sqlite3'"
sudo sqlite3 /var/lib/shards-kernel/github-operator/provider-journal.sqlite3 \
  ".backup '/var/backups/shards-kernel/provider-journal.sqlite3'"
sudo cp /etc/shards-kernel/github-operator.signed.json /var/backups/shards-kernel/
sudo systemctl start shards-kernel-github-operator.service
```

Recovery:

1. Keep the service stopped.
2. Restore the audit database and provider journal **from the same snapshot**.
   Do not pair a new journal with an old audit database or the reverse.
3. Restore the signed policy that matches that snapshot.
4. Start the service, verify `/health`, `/status`, then submit a new signed
   permit for a test issue and confirm the read-back.
5. Inspect any `UNKNOWN` journal rows before issuing new permits.

Rollback:

- The signed-policy checkpoint records the highest accepted revision and
  refuses an older revision. A rollback therefore requires restoring the audit
  database checkpoint and the signed policy from the same backup, or issuing a
  new higher-revision policy. Do not lower only the JSON revision.
- If the journal is lost, treat every possibly dispatched operation as
  `UNKNOWN` and reconcile the issue manually. Do not assume no effect.
- If the audit database is lost, do not start: replay protection is gone.
  Restore the audit backup first.

## Live GitHub acceptance

The normal suite never contacts GitHub. A gated acceptance test runs only when
the operator supplies a disposable test repository:

```bash
export SHARDS_KERNEL_LIVE_GITHUB_TOKEN='<fine-grained token>'
export SHARDS_KERNEL_LIVE_GITHUB_REPO='your-org/your-test-repo'
export SHARDS_KERNEL_LIVE_GITHUB_ISSUE='123'
export SHARDS_KERNEL_LIVE_GITHUB_LABEL='shards-agent'
# Optional write exercise against the disposable repository:
export SHARDS_KERNEL_LIVE_GITHUB_WRITE='1'
python -m pytest -q tests/test_github_issue_label_live.py
```

Without `SHARDS_KERNEL_LIVE_GITHUB_WRITE=1` the test performs a read-only
authoritative read-back. The token is never printed.

## Static-analysis triage at this revision

At checkpoint `f080c7f`, Codacy Static Code Analysis reported 13 annotations:
the 12 previously triaged below plus a new B101 `assert` warning on
`scripts/ops/reconcile_provider_effects.py:191`. That new finding was
remediated in the follow-up commit by replacing the assert with
`typing.cast`; the remaining 12 are unchanged. Codacy check-run IDs are
ephemeral and will differ at the next HEAD. CodeFactor continues to report
the single old B104 negative-assert finding.

The detailed rule pages are sign-in gated. The list below is taken from the
public GitHub check-run annotations and current source. It is a source-backed
triage, **not** a scanner-verified dismissal and not a claim that the checks
pass. No scanner rule or configuration was changed to silence a finding.

| # | Path:line | Scanner message | Classification | Source-backed rationale |
| --- | --- | --- | --- | --- |
| 1 | `shards_kernel/cli/service.py:48` | Possible hardcoded password: `'SHARDS_KERNEL_GITHUB_'` | False positive | Constant is an environment-variable **name prefix**; no credential value. |
| 2 | `shards_kernel/cli/service.py:48` | Possible hardcoded secret key | False positive | Same name prefix; values are read from the environment at runtime. |
| 3 | `shards_kernel/cli/service.py:49` | Possible hardcoded password: `'SHARDS_KERNEL_GATEWAY_'` | False positive | Gateway environment-variable name prefix; not a secret. |
| 4 | `shards_kernel/cli/service.py:49` | Possible hardcoded secret key | False positive | Same name prefix; no secret material is stored. |
| 5 | `shards_kernel/sdk/server.py:304` | Hardcoded tokens are a security risk | False positive | Line is the `gateway_token: Optional[str]` function parameter annotation; no literal token. |
| 6 | `tests/github_issue_label_test_server.py:26` | Redefining built-in `format` | False positive (stdlib signature) | `BaseHTTPRequestHandler.log_message(self, format, *args)` override must keep the stdlib parameter name. |
| 7 | `tests/test_github_issue_label_live.py:58` | Possible hardcoded password: `'SHARDS_KERNEL_LIVE_GITHUB_TOKEN'` | False positive | Environment-variable name used by the gated live test; the value is supplied externally. |
| 8 | `tests/test_github_issue_label_provider.py:284` | Possible hardcoded password: `'ghp_UNIQUE_SECRET_TOKEN_0123456789'` | False positive (test sentinel) | Deliberately fake token used to assert it never appears in outcome errors or logs. |
| 9 | `tests/test_github_issue_label_provider.py:676` | Possible hardcoded password: `'lowercase'` | False positive (negative path) | Input for a test asserting an invalid `token_env` name is rejected. |
| 10 | `tests/test_github_operator_deploy_contract.py:60` | Possible binding to all interfaces | False positive | String appears only in `assert "0.0.0.0" not in unit`, a negative assertion. |
| 11 | `tests/test_operator_github_profile.py:254` | Possible hardcoded password: `'SHARDS_KERNEL_API_KEY'` | False positive (negative path) | Input proving a reserved operator secret name is rejected as a provider token env. |
| 12 | `tests/test_operator_github_profile.py:255` | Possible hardcoded password: `'SHARDS_KERNEL_github_TOKEN'` | False positive (negative path) | Input proving a mixed-case invalid token env name is rejected. |
| 13 | `tests/test_github_operator_deploy_contract.py:59` | CodeFactor B104: possible binding to all interfaces | False positive | The only `0.0.0.0` literal is the negative assertion at line 60; line 59 is `assert required in unit`. |
| 14 | `scripts/ops/reconcile_provider_effects.py:191` (at `f080c7f`) | Codacy B101: use of `assert` | Remediated (not suppressed) | Replaced with `typing.cast(str, kernel_id)`. The removed post-load `AUDIT_LEDGER_EMPTY` check was unreachable because `available` is derived from the same `audit_entries` table; the reachable empty-table guard remains and is covered by `test_reconcile_rejects_empty_ledger_and_unknown_kernel`. The module measures 100% statement and branch coverage. |

Open question for an independent reviewer: confirm whether Codacy's hidden
rule metadata agrees with this mapping. Until then, these findings are
triaged as false positives or test-only artifacts, not proven vulnerabilities
and not "resolved".

## Validation at this revision

Local evidence (Python 3.13.15, Linux x86_64 container; CI matrix not executed
here):

```text
tests/test_github_issue_label_provider.py        51 passed
tests/test_operator_github_profile.py            35 passed
tests/test_provider_effect_reconciliation.py     17 passed
tests/test_public_tool_registration.py           11 passed
tests/test_github_operator_deploy_contract.py     3 passed
tests/test_github_issue_label_live.py             1 skipped (gated secrets)
```

The full suite (with the optional MCP SDK installed, as CI does) reports 1311
passed and 40 skipped, with ten `test_offline_approver_cli.py` tests failing in
this container because the filesystem rejects `O_TMPFILE` (`Errno 95`); those
ten pass when `TMPDIR` is tmpfs (`55 passed`), so the failure is
environment-dependent, not a profile regression. Branch coverage measured
93.19% with
`--cov=shards_kernel --cov=implementations --cov=scripts.ci.run_e2e_gate --cov=scripts.ops.reconcile_provider_effects --cov-branch --cov-fail-under=90`
on that same run. The mandatory four-scenario E2E gate passed (`4 passed`).
The provider module itself measures 99% and the journal 97% in the focused
run; the new reconciler measures 100% statement and branch coverage in
`tests/test_provider_effect_reconciliation.py`.

The new incident regression is covered by
`test_outcome_audit_failure_after_provider_effect_is_incident` (single POST,
journal `SUCCEEDED`, kernel `HALTED`, no fabricated outcome, same-process
admission denied, read-only reconciliation flags the mismatch) and
`test_incident_restart_boots_idle_but_never_repairs_old_outcome` (restart
boots `IDLE`, original permit replay-denied, new permit `already_present` with
no second POST, old missing outcome not backfilled). An earlier full-suite run
saw the mTLS two-process staging test fail once under concurrency; it passed
when run alone and in the final full-suite run, so treat it as an environment
flake, not acceptance evidence.

This is local test evidence only. It does not prove a Cloudflare path, an
ARM64 systemd start, GitHub production permissions or a remote deployment.

## Known gaps and hard blockers

1. **HARD BLOCKER: Cloudflare Edge federation is not implemented.** The live Edge is a
   separate product and must not be modified by this change. The Edge-side
   authenticated call path, identity mapping and deployment are a hard blocker
   for end-to-end remote use.
2. **HARD BLOCKER: Tunnel/reverse-proxy ingress configuration is not implemented.** The
   operator-side contract is implemented; the actual Cloudflare Tunnel or
   reverse-proxy configuration and its independent authentication are a hard
   blocker for deployment.
3. **Gateway authentication is a shared secret**, not mTLS. A compromised
   proxy can impersonate the gateway. Use a protected environment file and
   rotate the token.
4. **GitHub credential is a fine-grained token**, not a GitHub App
   installation token. Automatic rotation and short-lived installation tokens
   are not implemented.
5. **Single-host SQLite journal.** No HA, distributed locking or cross-host
   failover. Safety is preferred over availability.
6. **No exactly-once guarantee.** Ambiguous writes are quarantined as
   `UNKNOWN`; manual reconciliation is required.
7. **No automatic retry.** A new signed permit and request id are required.
8. **No label removal, merge, close or delete.** A human must reverse a label
   in GitHub.
9. **No rate-limit-aware backoff.** A 429 is quarantined as `UNKNOWN`.
10. **ARM64 systemd unit was reviewed but not executed in this sandbox.** Run
    `systemd-analyze verify` and a staging start on the target host before
    production use.
11. **No independent production acceptance.** CI and local tests do not prove
    a remote deployment, a live Cloudflare path or GitHub production
    permissions.
12. **REMAINING BLOCKER: restart is not reconciliation-enforced.** A provider
    effect applied with a journal `SUCCEEDED` but no audit outcome HALTs the
    kernel in memory. A process restart boots `IDLE` from the restored chain;
    it does not require the operator incident runbook to have completed. The
    provider preflight still prevents a duplicate POST and the original permit
    is replay-denied, but audit completeness is not automatically repaired.
    Use the read-only reconciliation tool and the external incident record
    before any approved restart.
