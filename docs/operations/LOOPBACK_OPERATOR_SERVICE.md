# Operator-managed loopback HTTP service (single host, pre-production)

This operator entrypoint is **not production-certified**. It provides an
installable local process that boots Shards-Kernel with a real UTC clock,
strictly allowlisted tools, pinned Ed25519 public keys and a SQLite audit
ledger. It rejects all configurations containing private signing material,
unknown fields, unsafe tool names, remote bind addresses or HMAC keys.

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
shards-kernel serve --config /absolute/path/to/service.json
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
1. The operator JSON configuration is schema-validated but **not signed**;
   filesystem and deployment provenance are not cryptographically attested.
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
