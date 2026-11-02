# Official MCP v2 — authenticated two-agent *local* relay

The `shards-kernel mcp-relay` command is a **stdio MCP adapter** to the
existing **signed v2 operator** on `127.0.0.1`. Each MCP client launches a
separate relay with its own agent credential. The relay is **NOT** an
Internet-facing MCP server, a wallet gateway, an independent operator, a
permit issuer, or a substitute for authenticated remote MCP.

## Trust and data flow

```text
MCP Client A (local)                 MCP Client B (local)
       | stdio JSON-RPC                   | stdio JSON-RPC
  MCP relay A                        MCP relay B
  bearer = agent-alpha.*             bearer = agent-beta.*
       | only POST /submit                | only POST /submit
       +----------------+-----------------+
                        |
           127.0.0.1:<signed-operator-port>
             signed operator policy v2
            token scrypt + actor binding
             per-agent tool allowlist
            separate signed Ed25519 permit
                audit/replay ledger
                        |
                echo / add ONLY
```

1. In a trusted operator provisioning environment, enroll **two separate**
   high-entropy agent-labelled credentials with
   `agent_token_kdf(token, pepper)` and put ONLY the derived scrypt
   verifiers in the signed operator v2 configuration. Sign the configuration
   with the separately held operator-policy Ed25519 signing key.
2. Start `shards-kernel serve --config /absolute/path/to/signed-v2.json`
   using a secret-manager-provided `SHARDS_KERNEL_API_KEY`, separately
   pinned `SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX`, and
   `SHARDS_KERNEL_AGENT_AUTH_PEPPER`. No unsigned-policy bypass.
3. Each client runs a separate official MCP v2 stdio process:

```bash
# These variable values must be provisioned by the trusted MCP client host;
# don't save them in a repository or paste them into an LLM prompt.
shards-kernel mcp-relay --port 8765
```

The relay receives only `SHARDS_KERNEL_AGENT_TOKEN` from the host's secure
environment. It must be a signed-config-enrolled value of the form
`agent-alpha.<random-48-byte-url-safe-token>`, never the operator bearer.
The operator port is an integer; no arbitrary URL, host, network IP or
HTTP path can be configured. The relay's only outbound destination is
`127.0.0.1:<port>/submit`, and it never follows redirects or retries.

The SDK handles protocol negotiation and tool discovery. The MCP tool list
contains **only** `governed_execute`, with arguments:

```json
{
  "name": "echo",
  "arguments": {"text": "approved-example"},
  "permit": {"EXACT_V2_SIGNED_PERMIT_FIELDS": "provided by separate issuer"}
}
```

The `permit` object is the actual v2 Ed25519 permit issued by a protected
operator, bound to the agent subject, expected kernel audience, action,
arguments and expiration. **The placeholder above is not executable**.
The relay never signs a permit or accepts any `actor`, bearer, endpoint,
headers, kernel request ID or operator privilege from MCP tool arguments.

On submission, the signed-policy operator verifies the agent token against
its per-agent scrypt registry, matches the server-derived principal to the
request actor, checks the per-agent tool allowlist, and only then evaluates
the independent signed kernel permit and persistent replay evidence.

The MCP result distinguishes a kernel `ALLOW` from HTTP 200 + kernel
`DENY`; missing, altered, expired or replayed permits return MCP errors.
Connection failures, unexpectedly large responses and uncorrelated receipts
also fail closed. Neither token nor request headers appear in MCP replies.
Do not expose the permit value in public traces: it is an authority-bearing,
short-lived capability.

## Test evidence

```bash
python -m pip install -e ".[dev,crypto,mcp]"
pytest -q tests/test_mcp_agent_relay.py
```

The integration suite launches a signed v2 operator in one real Python
interpreter and **two separate official MCP SDK stdio processes**, one per
agent. It checks tool discovery, distinct credentials, unsigned denial,
cross-agent permit denial, per-tool policy, approved one-shot actions
(`echo` and `add`), replay refusal and forced operator process restart
with recovered replay state. It also checks malformed tokens, invalid ports,
unavailable operator and bounds on tool argument serialisation. These tests
run where the optional MCP v2 dependency is installed (Python 3.11+).

## Release blockers — not production certified

This only proves **local MCP interoperability** with the separately
authenticated loopback HTTP operator. It does not provide remote transport,
OAuth/OIDC/mTLS, proof-of-possession credentials, Kubernetes service identity,
MCP network authentication, distributed atomic nonce transactions,
independent audit anchors, real KMS/HSM issuer custody or safe DEX/wallet
execution. Any process sharing the same OS account may be able to inspect
another process's environment; separate OS isolation and secret managers are
still required. A malicious client with possession of another agent's token
can impersonate it. There is no protocol-level client attestation here.

Do not expose the operator socket or relay over a public network.
Do not use the test/demo tokens in real infrastructure.

See [#79](https://github.com/Shards-foundation/Shards-kernel/issues/79)
and [#64](https://github.com/Shards-foundation/Shards-kernel/issues/64).
