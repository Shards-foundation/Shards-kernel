# Signed mTLS ingress (HTTPS boundary; NOT native remote MCP)

The `shards-kernel mtls-ingress` entrypoint is a **separate HTTPS reverse
boundary** in front of the existing **loopback-only** signed-policy operator.
It uses Python's standard-library TLS v1.3 server, enforces mandatory
client certificates and additionally pins the **exact SHA-256 fingerprint
of each authorised leaf certificate** in an independently Ed25519-signed
ingress policy.

This is a restricted reference for remote authenticated **HTTP** calls.
It is NOT a network-exposed MCP Streamable HTTP server, and it is NOT a
production-approved remote agent gateway.

## Trust layout

```text
External agent A                                 External agent B
  client TLS certificate A                         client TLS certificate B
  agent-alpha high-entropy bearer                   agent-beta high-entropy bearer
           | mTLS 1.3 HTTPS                                  |
           +------------------+-------------------------------+
                              |
                   Signed mTLS ingress policy
                   pinned Ed25519 trust root
                   TLS CA chain verification
                   exact per-agent leaf SHA256
                   cert actor == bearer label == request actor
                   POST /submit ONLY
                              |
                   127.0.0.1:<operator-port>
                   signed v2 operator policy
                   separate agent scrypt verification
                   independent Ed25519 permit verification
                   scoped echo/add -> audited receipt
```

Neither the HTTPS ingress nor the connecting agents have access to
the operator's bearer, its `/halt`, `/evidence`, `/status`, or
`/policy` endpoints. The ingress cannot issue permits and never
accepts an arbitrary host, URL, HTTP headers or forwarding path from
clients. Its sole backend is the local operator `POST /submit`.
A valid certificate by itself cannot execute: the independently enrolled
agent bearer and one-use Ed25519 permit are still mandatory.

## Policy and deployment

The trusted operator must first provision a server TLS key/certificate,
a client-auth CA certificate, and **separate client certificates** for
two enrolled agents. Follow a proper CA and key lifecycle; do not save
test keys or operator signing keys in git.

**Signed ingress-policy v2 is required for any non-loopback listener.**
Legacy v1 signed envelopes remain supported on loopback for compatibility
only, with no persistence-backed revision check. The v2 envelope signs an
explicit positive `revision`, fixed `ingress_id` and
`checkpoint_db_file` as well as the existing TLS and agent configuration.
The host operator must independently provision this private persistent file
before starting ingress:

```bash
install -m 0600 /dev/null /secure/ingress/ingress-checkpoint.sqlite3
```

The path must be absolute, a regular non-symlink file, owned by the service
user, and inaccessible to group/other users. **Creating the empty file is not
enough to activate ingress.** The trusted host operator must initialise it
**once, out of band**, after verifying the operator-signed v2 policy:

```bash
# Run as the same service user that owns the private checkpoint file.
export SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX='<independently-pinned-public-key-hex>'
python - /absolute/path/signed-ingress.json <<'PY'
import os
import sys
from shards_kernel.common.time import SystemClock
from shards_kernel.integrations.mtls_ingress import load_ingress_policy
from shards_kernel.integrations.mtls_checkpoint import bootstrap_ingress_checkpoint

config = load_ingress_policy(
    sys.argv[1],
    pinned_public_key_hex=os.environ["SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX"],
    now_ms=SystemClock().now_ms(),
)
if not (config.revision and config.checkpoint_db_file
        and config.ingress_id and config.policy_digest):
    raise SystemExit("Refusing to bootstrap legacy or incomplete ingress policy")
bootstrap_ingress_checkpoint(
    config.checkpoint_db_file,
    ingress_id=config.ingress_id,
    revision=config.revision,
    digest=config.policy_digest,
)
PY
```

Do not run this bootstrapping operation during ingress startup or as part
of automated recovery. Once the checkpoint is enrolled, subsequent starts
**require the existing table and signed ingress identity**: missing tables
or rows, damaged databases and unexpected file replacements fail closed.
An administrator must investigate a missing checkpoint and obtain
independently verifiable recovery authority; restoring an old database
alone is not proof of authorisation. Keep the **same file** across restarts
and policy rotations; preserve it in protected backups. The v2 service
transactionally remembers the highest accepted signed revision and digest.
A lower revision, a different signed config at the same revision, a missing
checkpoint or replacement of the file while the process runs fails closed.
On a newer signed revision, old running instances reject subsequent calls.

A reference *unsigned* configuration object to sign is:

```json
{
  "ingress_id": "production-agent-ingress",
  "checkpoint_db_file": "/secure/ingress/ingress-checkpoint.sqlite3",
  "listen_host": "127.0.0.1",
  "listen_port": 9443,
  "operator_port": 8765,
  "tls_cert_file": "/secure/ingress/tls-server.pem",
  "tls_key_file": "/secure/ingress/tls-server-key.pem",
  "client_ca_file": "/secure/ingress/client-ca.pem",
  "agents": [
    {"actor": "agent-alpha", "client_cert_sha256": "64_lowercase_hex_bytes_of_leaf_A"},
    {"actor": "agent-beta", "client_cert_sha256": "64_lowercase_hex_bytes_of_leaf_B"}
  ]
}
```

Only the trusted **offline** operator signs the object, using
`shards_kernel.issuer.sign_mtls_ingress_policy(config, signing_key,
issued_at_ms=..., expires_at_ms=..., revision=1)`. It creates a domain-separated
Ed25519 envelope `shards.mtls-ingress.v2` with an explicit monotonic revision.
Expiry must be at most 24 hours. This root key should be independent of permit signing and TLS keys.

The ingress service receives **only** the independently pinned
`SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX` and the signed JSON file.
No signing secret is loaded by the service. For local-only verification:

```bash
python -m pip install -e ".[crypto]"
shards-kernel mtls-ingress --config /absolute/path/signed-ingress.json
```

An external bind, such as a specifically assigned signed
`listen_host="192.0.2.44"` (documentation-only address), is
**refused by default** and additionally requires the explicit operator
flag `--allow-remote-listen`. **Legacy v1 envelopes are rejected for remote binds even with this flag.** Wildcard binds are not supported. In a
real deployment use an actual interface address assigned to that host.
The backend operator always stays on
`127.0.0.1`; never enable `allow_remote_bind` for the kernel itself.

The operator signs and reviews exactly which two agent identities own
which client-certificate fingerprints. A client must satisfy the CA
chain, the certificate pin, its actor-labelled bearer, the separately
signed operator agent registry and the Ed25519 execution permit.
The gateway does not infer agent identity merely from certificate CN.

## Test

```bash
python -m pip install -e ".[dev,crypto]"
pytest -q tests/test_mtls_agent_ingress.py tests/test_mtls_ingress_checkpoint.py
```

The live test generates a temporary CA, TLS 1.3 server identity and
three client certificates. Two are enrolled and one shares the same CA
but is **not pinned**. The test proves:
- TLS handshake rejection without a client certificate.
- Rejection of a valid-CA but unpinned client certificate.
- Rejection of certificate A with agent B's bearer or request identity.
- Rejection of incorrect bearer secrets, missing permits, and privileged paths.
- One permitted `echo` action for A, one permitted `add` action for B.
- Replay refusal after the first authorised execution.
- Invalid, tampered, expired or trust-root-mismatched policies refuse startup.
- Remote network bind is refused unless separately authorised.

## Important limitations

- This is a **TLS transport reference**. There is no official MCP
  Streamable HTTP handling, OIDC or JWT issuer validation in this server.
  An MCP stdio relay on another trusted machine would require a
  properly pinned HTTPS/mTLS client implementation before it can call it.
- It is a single-host sidecar relying on the loopback operator's local
  SQLite ledger, UTC clock and signed policy; cross-host replay and
  atomic external side-effect reconciliation are NOT demonstrated.
- TLS server key and client leaf private keys must be protected by the
  operator's own secret infrastructure. CRL/OCSP, automated certificate
  renewal, post-compromise trust-anchor rotation and secrets vaulting are
  not implemented; operator certificate pin removal/re-signing is manual.
- Signed v2 policy adds an explicit monotonic revision, deliberate one-time
  trusted-operator bootstrap and local SQLite checkpoint. Service startup
  never implicitly enrols an empty/deleted database. This is **not externally anchored**: a privileged actor who
  restores an old policy and its old checkpoint database together can evade
  local rollback detection. A trusted external anti-rollback anchor and
  safe recovery/rotation operations remain P0 work. The runtime's checkpoint
  validation uses explicit exceptions (not Python assertions), and the test
  suite verifies it remains fail-closed under Python's optimised `-O` mode.
- The reference ingress now admits at most 32 concurrent TLS connections,
  performs TLS handshakes in bounded worker threads (3-second handshake
  timeout), applies a 3-second socket-read timeout, and enforces separate
  8-second monotonic aggregate deadlines for HTTP request-line/header parsing
  **and** request-body receipt. Each blocked byte read is bounded by the
  remaining deadline, so slow clients cannot reset the budget indefinitely.
  Excess connections are closed before HTTP handling. These are **local resource bounds**, not a substitute for
  network-edge connection controls, a DDoS service or independently measured
  throughput under attack.
- No network segmentation proof, vulnerability assessment under hostile
  network load, production rate limits, DDoS controls, host hardening,
  real deployment, SLO measurement or remote two-OS-host verification.
- **No arbitrary tools, wallet signing, DEX, perps or live capital.**

Release work remains in
[issue #79](https://github.com/Shards-foundation/Shards-kernel/issues/79),
[issue #64](https://github.com/Shards-foundation/Shards-kernel/issues/64) and
[issue #63](https://github.com/Shards-foundation/Shards-kernel/issues/63).


## Checkpoint SQLite connection lifecycle (security hardening)

The signed v2 ingress opens a transaction when checking every authenticated
request. SQLite's Python connection context manager **does not automatically
close its file descriptor**; it only commits or rolls back. The checkpoint
helper now wraps every transaction with explicit connection closure on
successful verification, bootstrap, revision advancement and failures.
Repeated authentication must not depend on cyclic garbage collection to
release descriptor capacity. Regression coverage retains 125+ live
connection references to prove that all SQLite handles were explicitly
closed before another request.

This mitigates local file-descriptor exhaustion, **not** hostile network
load or upstream denial-of-service: admission limits, deadline enforcement,
network firewalls and platform monitoring remain independent release gates.
