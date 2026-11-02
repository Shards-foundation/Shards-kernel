---
name: governed-mcp-agent
description: Connect a separately enrolled AI agent to Shards-Kernel's current official local MCP stdio relay, discover governed_execute, submit an independently signed permit, and verify ALLOW/DENY without leaking credentials. Use for agent onboarding, local SDK integration, or MCP troubleshooting.
license: MIT
---

# Governed local MCP agent

## Scope

This skill is for an **agent client**, not an operator, permit issuer, wallet signer or Shards MCP Gateway. The currently supported transport is the official MCP SDK v2 **stdio process** to `127.0.0.1:<signed-operator-port>/submit`. The operator owns authentication, signed-policy checks, permit verification, execution and durable audit. Only harmless built-in `echo` and `add` are available.

Never upgrade an agent to operator authority. Never create or disclose credentials to satisfy a test.

## Preconditions (verify; do not infer)

- Python 3.11+ with `shards-kernel[crypto,mcp]` installed.
- The trusted operator has started `shards-kernel serve --config /absolute/path/to/signed-v2.json` and is bound to loopback. No public/remote service is implied.
- This agent has a unique independently enrolled token with an `agent-name.<random-secret>` structure, injected by its trusted host in `SHARDS_KERNEL_AGENT_TOKEN`. Each agent must have a **separate** token and relay process.
- An independently issued **one-use Ed25519 v2 signed permit** covers the exact actor, audience, tool, arguments and expiry. A placeholder, self-signed request, or missing permit is not authority.
- Do not place agent tokens, operator credentials, signature-bearing permits, private keys, or secret manager output in GitHub issues, screenshots, telemetry or chat.

If any precondition is missing, return **BLOCKED**, say which trusted actor must supply it, and do not create an unsigned bypass.

## Connect with an MCP host

Configure the host to spawn the installed binary:

```json
{
  "command": "shards-kernel",
  "args": ["mcp-relay", "--port", "8765"]
}
```

`8765` is **an illustration**; use the actual loopback port from the signed operator policy. Do not copy a real token into this JSON. The host injects the enrolled agent token using its own secret manager.

Discover exactly one available tool, `governed_execute`, using the host's official MCP tool-discovery facility. Submit a narrowly scoped invocation:

```json
{
  "name": "echo",
  "arguments": {"text": "hello"},
  "permit": {"REPLACE_WITH_OPERATOR_ISSUED_SIGNED_V2_PERMIT": true}
}
```

The permit above is **intentionally not valid** and must not be run as-is. Obtain the signed object securely from a separate trusted issuer; do not fill it with invented keys or signatures.

The optional one-shot `shards-kernel mcp-call` interface is being reviewed in **PR #90**. Check `shards-kernel mcp-call --help` before using it; no skill may assume unreleased code is installed.

## Acceptance protocol

1. Confirm the MCP process negotiated with the SDK and exposes **only** `governed_execute`. Never accept arbitrary remote tool lists or an unexpected second tool.
2. Before submitting authority-bearing data, verify the known actor, signed permit scope, current operator port and expiry.
3. **Negative path:** a missing permit must be denied. A mismatched actor, unsupported tool and changed parameters must not execute.
4. **Positive path:** only an actual signed permit for the exact `echo`/`add` arguments may yield a kernel `ALLOW` and corresponding typed result.
5. **Replay path:** resubmitting the *same* one-use permit must return `DENY`; no automatic retry, re-sign or scope broadening.
6. **Recovery path:** if the operator is restarted with the same audited SQLite state, already-consumed permits remain denied.

For reproducible **test-only** proof, run:

```bash
python -m pip install -e ".[dev,crypto,mcp]"
pytest -q tests/test_mcp_agent_relay.py tests/test_operator_process_restart.py
```

Where PR #90's CLI and test files are present, additionally run `pytest -q tests/test_mcp_call_cli.py tests/test_mcp_call_e2e.py`. A test's ephemeral credentials are **not deployable identities**.

## Receipt and failure handling

Treat HTTP status 200 or an MCP success flag alone as **insufficient**: require a verified kernel `decision=ALLOW`. A malformed result, bad request ID, unexpected tool name, expired/used permit, nonfinite numeric result, timeout, or transport failure is a **hard DENY/ERROR**. Never retry a potentially executed action after a network failure without independent audit reconciliation.

Report only synthetic request IDs, decision categories, observed result types and test totals. Redact all bearer tokens and signed permit documents.

For details consult [official MCP two-agent relay](../../../docs/operations/MCP_TWO_AGENT_RELAY.md), [two-agent identity controls](../../../docs/operations/TWO_AGENT_IDENTITY.md), and [operator threat model](../../../docs/THREAT_MODEL.md).
