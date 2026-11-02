# Two independently authenticated local agents — operator policy v2

This **loopback-only** reference lets two or more independent clients use the
same Shards-Kernel process without sharing a bearer credential or claiming an
arbitrary `actor` field. This is **not** a remotely authenticated gateway:
there is no TLS ingress, OIDC, mTLS, externally attested agent identity,
cross-host quorum, or production secret-management integration.

## Enrollment and trust

The trusted operator provisions a **different 48-byte random secret** for
each agent via its existing approved secret manager. For example, the
operator can use `secrets.token_urlsafe(48)` on a protected terminal.
The raw value is transferred to **one** designated agent. It must **never**
be entered in a prompt, committed to git, logged by an LLM or embedded in
the signed operator config.

The operator records only **HMAC-SHA256 digests** of those tokens in the
signed policy, using a **separate operator-held, high-entropy MAC key**
`SHARDS_KERNEL_AGENT_AUTH_PEPPER`. That pepper is not stored in the policy.
The operator computes each lookup digest in a protected provisioning session
using `shards_kernel.integrations.auth.agent_token_mac(token, pepper.encode())`.
The operator injects the same pepper into the service independently of
the signed policy. A stolen config is not sufficient to test offline
guesses without the pepper, although token entropy must still be high.

The operator/halt bearer credential is independent and supplied via
`SHARDS_KERNEL_API_KEY`. Its token must never be shared with an agent.

### Example v2 operator configuration (public material only)

```json
{
  "version": 2,
  "kernel_id": "kernel-two-agents",
  "tools": ["echo", "add"],
  "agents": [
    {
      "actor": "agent-alpha",
      "token_hmac_sha256": "REPLACE_WITH_HMAC_SHA256_OF_UNIQUE_HIGH_ENTROPY_ALPHA_TOKEN",
      "allowed_tools": ["echo"]
    },
    {
      "actor": "agent-beta",
      "token_hmac_sha256": "REPLACE_WITH_HMAC_SHA256_OF_UNIQUE_HIGH_ENTROPY_BETA_TOKEN",
      "allowed_tools": ["add"]
    }
  ],
  "issuer_keys": [
    {
      "key_id": "operator-key-1",
      "issuer": "operator",
      "public_key_hex": "REPLACE_WITH_64_LOWERCASE_HEX_PUBLIC_KEY",
      "revoked": false
    }
  ],
  "audit_db": "/absolute/path/to/private/audit.sqlite3",
  "port": 8765
}
```

The service requires the independently supplied high-entropy
`SHARDS_KERNEL_AGENT_AUTH_PEPPER` to start in v2 mode. Changing this key
requires signed policy re-enrollment of all agent token digests.

The operator signs this configuration using the existing separate Ed25519
operator-policy signer (`shards.operator-policy.v1` envelope). V2 is the
**configuration schema version**: it does not change the envelope protocol
or the signed v2 Ed25519 **permit** format. Startup remains:

```bash
# Inject separate operator bearer and pinned policy public key securely.
shards-kernel serve --config /absolute/path/to/signed-two-agent-policy.json
```

There is no `--allow-unsigned-local` requirement for a valid signed
policy, and that bypass remains **development only**.

## Authorization sequence

1. An agent sends `Authorization: Bearer <its-own-credential>` to
   `POST /submit`. The server compares the HMAC-SHA256 of the presented
   credential (under the operator-held pepper) to all signed-config digests using constant-time comparisons.
2. The server resolves a **single pinned actor** from the credential.
   The request's JSON `actor` must match exactly, or the service returns
   HTTP **403** before kernel execution.
3. The requested tool must be in the resolved actor's own
   `allowed_tools` subset. Otherwise HTTP **403**.
4. Independently, Shards-Kernel verifies the **issuer-signed Ed25519
   permit**, its subject, intended audience, tool, parameters, expiry,
   max-executions, nonce/replay state and audit policy. A valid transport
   token alone **never grants execution**.
5. Authenticated clients receive a normal kernel receipt. Replay and
   wrong-subject permits are denied by kernel authorisation.

The operator credential **cannot be used to impersonate either agent**
at `POST /submit` in v2 mode. Agent bearers cannot access
`/status`, `/policy`, `/evidence`, or `/halt`: those require the
operator-only credential. `GET /health` remains unauthenticated, and
reveals only minimal process status.

## Compatibility and limitations

- v1 config with a single `actor` and operator bearer still works in
  local development. V2 `agents` and v1 `actor` **cannot be mixed**.
- V2 accepts between 2 and 16 unique actors and unique keyed bearer digests.
  Each agent gets a nonempty subset of the safe `echo` / `add`
  operator-wide tool list. No wallet, shell, remote code or dynamic tools.
- This is an **operator-provisioned token registry**, not cryptographic
  workload identity. Bearer tokens are replayable by anyone holding them.
  No mutual TLS, proof-of-possession, OAuth/JWT, short-lived token
  rotation service, or hardware key attestation has been implemented.
- Every process is loopback only on `127.0.0.1`. There is no safe
  remotely exposed HTTP listener here; do not publish the port.
- Local SQLite persistent time and audit replay protections do **not**
  provide cross-replica consensus or externally anchored history.
- Real independent remote MCP clients still need an authenticated
  MCP ingress implementation; v2 operator HTTP is an intermediate
  reference boundary, not proof of universal agent compatibility.

Tracked by [#79](https://github.com/Shards-foundation/Shards-kernel/issues/79),
[#68](https://github.com/Shards-foundation/Shards-kernel/issues/68)
and [#64](https://github.com/Shards-foundation/Shards-kernel/issues/64).
