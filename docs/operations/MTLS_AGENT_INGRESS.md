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

A reference *unsigned* configuration object to sign is:

```json
{
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
issued_at_ms=..., expires_at_ms=...)`. It creates a domain-separated
Ed25519 envelope `shards.mtls-ingress.v1`. Expiry must be at most 24
hours. This root key should be independent of permit signing and TLS keys.

The ingress service receives **only** the independently pinned
`SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX` and the signed JSON file.
No signing secret is loaded by the service. For local-only verification:

```bash
python -m pip install -e ".[crypto]"
shards-kernel mtls-ingress --config /absolute/path/signed-ingress.json
```

An external bind, such as a specifically assigned signed\n`listen_host="192.0.2.44"` (documentation-only address), is
**refused by default** and additionally requires the explicit operator
flag `--allow-remote-listen`. Wildcard binds are not supported. In a\nreal deployment use an actual interface address assigned to that host.\nThe backend operator always stays on
`127.0.0.1`; never enable `allow_remote_bind` for the kernel itself.

The operator signs and reviews exactly which two agent identities own
which client-certificate fingerprints. A client must satisfy the CA
chain, the certificate pin, its actor-labelled bearer, the separately
signed operator agent registry and the Ed25519 execution permit.
The gateway does not infer agent identity merely from certificate CN.

## Test

```bash
python -m pip install -e ".[dev,crypto]"
pytest -q tests/test_mtls_agent_ingress.py
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
- There is no signed monotonic ingress-policy revision high-water mark;
  the short expiry and pinned root do not provide external anti-rollback.
- Ingress request-line and HTTP headers share a **16 KiB cumulative byte
  limit**, including line terminators, in addition to the absolute 8-second
  parsing deadline. Oversized pre-authentication headers are rejected.
- `MTLSIngressServer.stop()` is a **forward-dispatch revocation boundary**:
  it prevents new operator forwarding before closing its listener and drains
  in-flight forwarding before returning. Already completed operator actions
  cannot be rolled back. Accepted sockets may finish TLS after shutdown
  starts, but must never dispatch new operator calls. A slow or hung trusted
  operator can delay stop while an earlier forwarding request drains.
- The reference ingress now admits at most 32 concurrent TLS connections,
  performs TLS handshakes in bounded worker threads (3-second handshake
  timeout), applies a 3-second socket-read timeout, and enforces separate
  8-second monotonic aggregate deadlines for HTTP request-line/header parsing
  **and** request-body receipt. Each blocked byte read is bounded by the
  remaining deadline, so slow clients cannot reset the budget indefinitely. Excess connections are closed before
  HTTP handling. These are **local resource bounds**, not a substitute for
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
