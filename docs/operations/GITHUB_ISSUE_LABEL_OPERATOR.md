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
`deploy/github-operator.config.example.json`. It contains no secrets.

Validation rules include:

- `owner`/`repo` are concrete GitHub names; no URLs, globs or path traversal.
- `allowed_labels` is a unique nonempty list of at most 32 exact names.
- `max_issue_number` is an integer between 1 and 10,000,000.
- `journal_db` and `audit_db` are absolute paths whose parent exists; symlinks
  and directories are refused.
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

This is **not** an exactly-once side-effect guarantee. If a request ends
`UNKNOWN`, a human must inspect the issue. A new action requires a new signed
permit and a new request id; the same permit is denied as a replay. The
provider's preflight read-back prevents a new authorised request from adding a
label that is already present.

Label addition is reversible only by a separately authorised human in GitHub.
The provider offers no delete, remove, merge or close operation.

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

## Validation at this revision

Local evidence (Python 3.13.15, Linux x86_64 container; CI matrix not executed
here):

```text
tests/test_github_issue_label_provider.py       30 passed
tests/test_operator_github_profile.py           21 passed
tests/test_public_tool_registration.py           8 passed
tests/test_github_operator_deploy_contract.py    3 passed
tests/test_github_issue_label_live.py            1 skipped (gated secrets)
```

The broader suite reports 1188 passed and 43 skipped with the offline-approver
module excluded. Ten `test_offline_approver_cli.py` tests fail in this
container because the filesystem rejects `O_TMPFILE` (`Errno 95`); that is an
environment limitation unrelated to this profile. One mTLS two-process staging
test failed once only when the whole suite ran concurrently and passed when
run alone; treat it as an environment flake, not acceptance evidence.

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
