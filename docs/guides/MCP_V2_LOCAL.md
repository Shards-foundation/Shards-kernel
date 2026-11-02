# Official MCP SDK v2 integration — local stdio reference

This is the first **SDK-backed** MCP transport for Shards-Kernel.
It delegates protocol version negotiation, discovery, JSON-RPC framing and
stdio lifecycle to the maintained Python MCP SDK. It is not a hosted MCP
Gateway and has not yet passed independent external-host interoperability
or a remote authentication assessment.

## Scope and security posture

- Python **3.11+**; install with `python -m pip install -e ".[mcp]"`.
- The base `shards-kernel` package remains installable on Python 3.9+.
- **Local stdio only**. The host starts one subprocess per trusted local
  agent identity. Do not expose this example over HTTP or a shared network.
- The trusted host provides a **fixed actor identity** to the factory. An
  untrusted LLM cannot set or override the actor through tool arguments.
- Only explicitly registered, named tool handlers may run. A signed permit
  bound to the actor, action, exact arguments and validity period is still
  required for execution. Missing/mismatched/replayed permits are denied.
- The kernel's wildcard default policy is rejected by the SDK bridge.
- Permit issuer signing keys must remain outside model prompts and tool
  arguments. A permit is an authority-bearing capability; do not persist it
  in a public log or allow arbitrary models to retrieve it.
- The current bridge is process-local. Distributed permit consumption,
  independent identity attestation, audit archive and remote auth are not
  implemented by this adapter.

## Start the local example

Prepare a high-entropy key and inject it through your local secret manager.
For an **ephemeral development-only** test environment:

```bash
python -m pip install -e ".[mcp]"
export SHARDS_KERNEL_MCP_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python examples/12_official_mcp_sdk_v2_stdio.py
```

That process produces no normal terminal output. It is waiting for an MCP
client to communicate over its stdin/stdout. The example uses a real UTC
millisecond clock so that short-lived permits expire. It registers only
`repeat(text)` via the single MCP tool `governed_execute`.
It **never** issues permits itself; the controlling operator must issue a
signed permit through a separate trusted workflow using the same kernel
keyring configuration. Until a valid permit is supplied, tool invocation
returns a denial.

Example local client configuration (adapt the command and path to your host):

```json
{
  "mcpServers": {
    "shards-kernel-local": {
      "command": "python",
      "args": ["/absolute/path/to/Shards-kernel/examples/12_official_mcp_sdk_v2_stdio.py"]
    }
  }
}
```

Configure `SHARDS_KERNEL_MCP_KEY` through the host's secure environment or
secret-management feature, **not** in a committed configuration file.
The exact configuration format depends on the host product and may differ.
A human operator must provide permits to the trusted invocation layer;
do not instruct a model to manufacture signatures.

## Connect and test

The official MCP SDK in-memory client tests are in
`tests/test_mcp_sdk_v2.py`. They cover server discovery, tool listing,
one authorised execution, permit replay rejection, missing permit denial,
subject mismatch and invalid permit format:

```bash
python -m pip install -e ".[dev,mcp]"
pytest -q tests/test_mcp_sdk_v2.py
```

To test a real host, run the example under its MCP client and confirm that
the client discovers `governed_execute`. A complete third-party host demo
with permitted execution is **not yet verified**. See
[issue #64](https://github.com/Shards-foundation/Shards-kernel/issues/64).

## Protocol compatibility

Uses the official MCP Python SDK **v2** (pinned within `>=2.2,<3`).
The SDK implements modern MCP 2026-07-28 protocol lifecycle/discovery and
legacy compatibility. Exact client, transport and version interoperability
must be verified as independent release evidence before v1.0 adoption.

Official references:
- https://py.sdk.modelcontextprotocol.io/get-started/testing/
- https://py.sdk.modelcontextprotocol.io/run/
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning

## Intentional limitations

This is a safe direction toward a usable Shards-Kernel, not a complete
cross-agent integration or production-certified gateway. The legacy
`shards_kernel.integrations.mcp_adapter.MCPServer` is a hand-written
subset and must not be confused with the official SDK's server type.
The recommended new factory is
`shards_kernel.integrations.mcp_sdk_v2.create_official_mcp_server`.
