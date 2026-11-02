# Operator-managed loopback HTTP service (single host, pre-production)

This operator entrypoint is **not production-certified**. It provides an
installable local process that boots Shards-Kernel with a real UTC clock,
strictly allowlisted tools, pinned Ed25519 public keys and a SQLite audit
ledger. It rejects all configurations containing private signing material,
unknown fields, unsafe tool names, remote bind addresses or HMAC keys.

## Signed operator policy required by default

Operator service startup now **requires an Ed25519-signed policy envelope**,
verified using a separate trust anchor supplied by
`SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX`. This public key is pinned by the
operator outside the signed document; the policy is never allowed to declare
its own verification key. Missing/incorrect anchors, tampering, expiry,
schema changes, unknown configuration fields, duplicate JSON keys and
signed-policy revision rollback cause a nonzero startup exit.

The **trusted signing process**, separate from the operator service and all
agent clients, uses `shards_kernel.issuer.sign_operator_policy`. This helper
accepts an already provisioned `cryptography` Ed25519 private key obtained
through the operator's existing KMS or offline custody controls. Never
create, store, log or expose that private key on the service host.

Signing-side Python illustration (in the independent trusted environment):

```python
import json
from shards_kernel.issuer import sign_operator_policy

# config is a carefully reviewed v1 operator configuration (public data only).
# signing_key is an Ed25519PrivateKey held ONLY in the trusted issuer process.
policy = sign_operator_policy(
    config, signing_key, revision=1,
    issued_at_ms=operator_time_ms,
    expires_at_ms=operator_time_ms + 24 * 3600 * 1000,
)
# Publish 'policy' through an integrity-protected operator delivery mechanism.
print(json.dumps(policy))
```

The resulting file has exactly these fields:
`schema="shards.operator-policy.v1"`, `revision`, `issued_at_ms`,
`expires_at_ms`, `config`, and `signature_hex`. The signed message is
`SHARDS-OPERATOR-POLICY-V1` followed by a zero byte and compact,
UTF-8, alphabetically sorted JSON of the first five fields. Signatures use
Ed25519, not the agent's Ed25519 **permit** key. Use distinct issuer and
operator-policy keys, held by separate authorities where practicable.

At service startup, use a protected operator environment:

```bash
export SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX="<64-character pinned PUBLIC key>"
# SHARDS_KERNEL_API_KEY must be injected securely by the operator's secret manager.
shards-kernel serve --config /absolute/path/to/signed-operator-policy.json
```

The service checks a real UTC clock at startup and for each authenticated
route; after `expires_at_ms`, it returns HTTP 503 and `/health` becomes
unhealthy. A local SQLite `operator_policy_checkpoint` records the
highest accepted revision and its signed digest for that kernel; older
revisions or a changed document at the same revision cannot restart the
service against that unchanged local database. An operator must increase
the revision for each policy change. **This is not a tamper-proof or
distributed anti-rollback anchor**: an attacker who deletes/replaces the
entire SQLite database or controls host environment/trust keys may bypass
the local revision record. External sealing, stable trusted time and key
revocation remain release blockers.

For backwards-compatible **development only**, an operator can explicitly run:

```bash
shards-kernel serve --config /absolute/path/to/unsigned-local.json --allow-unsigned-local
```

This bypass is limited to the same loopback-only built-in-tool runtime,
and is **not appropriate for staging or production**. It exists so existing
deterministic local tests remain usable; it must not be added to deployment
manifests.

## Provisioning

Install the package with its optional public-key verifier:

```bash
python -m pip install -e ".[crypto]"
shards-kernel doctor --profile service --json
```

Generate an Ed25519 keypair in a **separately protected operator issuer**,
not in the agent process and not in the Shards-Kernel service. Obtain its
32-byte raw *public* key encoded as 64 lowercase hexadecimal characters.

Create a JSON configuration **outside the repository**, replace the placeholder
values, and create the SQLite parent directory before startup:

```json
{
  "version": 1,
  "kernel_id": "operator-local",
  "actor": "local-agent",
  "tools": ["echo"],
  "issuer_keys": [
    {
      "key_id": "operator-key-1",
      "issuer": "operator",
      "public_key_hex": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
      "revoked": false
    }
  ],
  "audit_db": "/absolute/path/to/private/audit.sqlite3",
  "port": 8765
}
```

The file contains **public verification material only**. The service
requires a separate 32+ character bearer credential in the environment.
Inject it from a secret manager or equivalent protected operator session,
never commit it to git or share it with an LLM. Then run:

```bash
shards-kernel serve --config /absolute/path/to/signed-operator-policy.json
```

The process listens only at `127.0.0.1:<configured port>`. It never
binds a public network interface. Configure a narrow HTTP request
including `actor="local-agent"`; this value must match the single
operator-configured service principal and the signed permit `subject`.
The bearer credential is checked separately from Ed25519 permit authorization.

- `GET /health` reports **process-level status** only.
- `GET /status`, `GET /policy`, `GET /evidence`,
  `POST /submit`, `POST /halt` require HTTP bearer auth.
- `POST /submit` additionally needs a narrowly scoped Ed25519 v2 permit
  signed by the **external issuer** with `audience="operator-local"`.
  Missing permits, spoofed actors, wrong action/parameters and replay are
  denied by the kernel.
- The ledger is written to local SQLite before any authorised tool call,
  and its existing hash chain is verified when the kernel restarts.
  This also reconstructs previously used permit nonces.

An exclusive advisory lock held for the **entire process lifetime** refuses
another writer on the same local host / database. Do not deploy this
implementation on a network filesystem or across replicas.

## Independent-process restart verification

The test `tests/test_operator_process_restart.py` starts the real
`shards-kernel serve --config` CLI in a **spawned, separate Python
interpreter**. The issuer's Ed25519 private key remains in the parent test
process; the child receives only a JSON file with the **public** key.

The test authenticates HTTP with an independently generated bearer key,
verifies DENY without transport auth, DENY for a spoofed actor and ALLOW
for a narrowly scoped Ed25519 signed permit. It then forcibly terminates
the service process, starts a new interpreter with the same SQLite ledger,
compares the restored audit root and proves that reuse of the original
signed permit is denied as a replay.

```bash
python -m pytest tests/test_operator_process_restart.py -q
```

This is a real process crash/restart integration test but **not** a side
effect reconciliation proof. The only permitted tool is a deterministic
in-process `echo`; no distributed worker, externally committed transaction
or multi-host nonce registry is involved.

## Deliberate scope restrictions

The operator config format allows only exactly the built-in, deterministic,
non-financial tools `echo` and `add`. No arbitrary imports, shell
commands, wallets, external destinations, cron jobs, background workers,
dynamic registry entries or policy-wide wildcard grants.

**Unresolved blockers:**
1. Operator policy is now signed by an out-of-process Ed25519 signer, but
   the configured root of trust, host filesystem, and deployment provenance
   are not cryptographically attested; unsigned local bypass remains possible.
2. A single bearer token authenticates one local principal but cannot
   distinguish independent services/agents or operator halt authority;
   there is no TLS ingress, OAuth/OIDC, mTLS or remote identity.
3. SQLite locking is only local-host advisory; no distributed, transactional
   nonce consumption across processes on different hosts.
4. SQLite integrity checking can detect modified hashes but cannot detect a
   fully removed history without an external trusted checkpoint/anchor.
5. The private signing key is not handled by this service; an independent
   audited issuer, protected key storage and key rotation propagation are
   required.
6. There is no tested host supervision, malicious-local-user threat model,
   signed backups, crash-during-side-effect reconciliation or security
   certification.

Consequently `shards-kernel doctor --profile service` must continue to
report **NOT_READY**, including when the local loopback service runs.
Do not connect trading agents, wallets or externally reachable MCP tools.

See issues [#69](https://github.com/Shards-foundation/Shards-kernel/issues/69),
[#68](https://github.com/Shards-foundation/Shards-kernel/issues/68),
[#66](https://github.com/Shards-foundation/Shards-kernel/issues/66)
and [#63](https://github.com/Shards-foundation/Shards-kernel/issues/63).
