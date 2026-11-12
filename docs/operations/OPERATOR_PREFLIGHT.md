# Operator preflight: `shards-kernel doctor`

The diagnostic CLI is an offline, read-only check of the **installed**
Shards-Kernel environment. It does not start a service, mint permits, access
private signing keys, invoke tools, or connect to remote infrastructure.

## Commands

```bash
python -m pip install -e ".[dev,crypto,mcp]"
shards-kernel doctor --profile library
shards-kernel doctor --profile service
shards-kernel doctor --profile service --json
```

In the development CLI, `library` is the default profile; the already
published v0.1.3 wheel still defaults to `service`. For consistent,
unambiguous results, **always specify the intended profile**. A service
operator must run `shards-kernel doctor --profile service` explicitly.
The process exits **0** only when all checks in the selected profile are
`PASS`; otherwise it exits **2**. The `library` profile establishes
basic local SDK prerequisites, **never** readiness of the operator service.
A `NOT_VERIFIED` service gate must not be relabelled as a library failure.

## Diagnostic contract

| Check | Evidence or limitation |
|---|---|
| `python` | Python runtime version >=3.9 |
| `clock_primitive` | Local SystemClock probe, not cross-restart time integrity |
| `ed25519_library` | Importable cryptography package |
| `mcp_sdk` | Optional official MCP SDK installed under Python >=3.11 |
| `http_credential` | `SHARDS_KERNEL_API_KEY` is syntactically acceptable; value never printed |
| `trusted_issuer` | **NOT_VERIFIED** until operator approvals, public keys and issuer trust are deployed |
| `durable_evidence` | **NOT_VERIFIED** until append, restore and replay recovery are demonstrated |
| `gateway_security` | **NOT_VERIFIED** until remote TLS, agent identity and authorisation are tested |

A passing `http_credential` check means only that the environment contains a
well-formed string. It does not establish that the secret is securely stored,
rotated, scoped or provisioned to a deployed service. A passing clock primitive
check does not prove NTP safety, trusted time or consistency across restarts.

**Important:** this is a truthful diagnostic placeholder for unresolved
deployment gates, not a mechanism to waive them. In a later PR, live runtime
evidence and separately authenticated issuer state must be integrated into the
readiness decision. The service profile intentionally remains nonzero until then.

## Machine-readable example

```bash
shards-kernel doctor --profile service --json
```

The output includes `version`, `profile`, `assessment`, `ready` and
individual checks with `id`, `status` and `detail`. The caller should treat
`NOT_VERIFIED` as a blocker, never as an informational or warning-only status.

Related: [production-readiness programme](https://github.com/Shards-foundation/Shards-kernel/issues/63)
and [operator onboarding work](https://github.com/Shards-foundation/Shards-kernel/issues/69).
