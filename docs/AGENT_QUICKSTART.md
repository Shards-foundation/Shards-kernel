# Get an agent using Shards-Kernel (local reference release)

**Status:** executable local MCP integration, not a production network gateway.
This is the smallest currently supported agent-facing contract. The future
**Shards MCP Gateway is a separate, not-yet-created product**. You do not need
that gateway to demonstrate a fully governed local tool invocation today.

## 1. Install

Use a private local checkout or a Git SHA pinned by your release manager.
Python **3.11+** is required for the official MCP SDK v2 integration:

```bash
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[crypto,mcp]"
shards-kernel --version
shards-kernel demo --json
shards-kernel doctor --profile library --json
```

The offline `demo` shows **DENY → ALLOW → replay DENY → revoked DENY**
with verified evidence, without deploying an operator or issuing credentials.
This is a deterministic demonstration, not a network service.

## 2. Enrol your agent and start the operator

To execute a **real MCP agent call**, provision the signed v2 operator as
specified in [Two-agent identity](operations/TWO_AGENT_IDENTITY.md) and
[Official MCP relay](operations/MCP_TWO_AGENT_RELAY.md). The trust boundary is:

```text
External trusted approver / issuer -- signs exact one-use permit
                                       |
Agent process -- official MCP stdio -- local relay (ONE agent bearer)
                                       |
                             HTTP 127.0.0.1:<port>/submit
                                       |
                    Signed v2 operator policy / agent registry
                                       |
                     Kernel permits → audit → echo/add only
```

An independently trusted operator must supply the following **outside this
repository**:

- An Ed25519-signed v2 operator policy containing the allowed agent actor,
  its **scrypt token verifier**, allowed `echo`/`add` tools, and pinned
  permit-issuer **public** verification key.
- One enrolled agent token in `SHARDS_KERNEL_AGENT_TOKEN`, with format
  `agent-name.<high-entropy-secret>`. Never share or print it. No operator
  API key or signing key is supplied to the agent.
- A separately signed, unexpired, **single-execution** v2 permit saved as a
  private, operator-owned, regular **0600** JSON file under an absolute path.
  The permit must bind the agent, exact action/arguments, intended kernel
  audience and issuer. The agent never creates or signs that permit.
- The operator service with `SHARDS_KERNEL_API_KEY`,
  `SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX` and
  `SHARDS_KERNEL_AGENT_AUTH_PEPPER` securely injected into **the
  operator process**, not the agent process.

Then on the trusted operator host:

```bash
shards-kernel serve --config /absolute/private/path/to/signed-v2-operator.json
```

The operator listens on **127.0.0.1 only**; no public binding, reverse proxy
or remote wallet/signing privileges are needed.

## 3. Make a governed tool call from an enrolled agent

On the **same host**, in a process with only that agent's credential injected
by its trusted launcher, run:

```bash
shards-kernel mcp-call \
  --port 8765 \
  --tool echo \
  --arguments-json '{"text":"Hello from my agent"}' \
  --permit-file /absolute/private/path/to/issued-echo-permit.json
```

The MCP client starts a **new stdio relay subprocess** using the installed
Python interpreter. The subprocess is passed only the agent bearer through
its environment. The MCP protocol handles connection/lifecycle, tool
discovery and the `governed_execute` request. No agent-supplied network
destination, privileged endpoint, signer or actor override is accepted.

The client prints machine-readable JSON only, for example:

```json
{"decision":"ALLOW","request_id":"mcp-relay-...","result":"Hello from my agent"}
```

Expected exit status: **0 only on an explicitly verified kernel ALLOW**,
otherwise **2** with a bounded `DENY` JSON error. The same signed permit
cannot be reused; the operator reconstitutes consumed permits on SQLite
recovery. A missing permit, forged agent identity, mismatched parameters,
wrong tool, unavailable operator or invalid MCP response fails closed.

Use `--tool add --arguments-json '{"a":2,"b":3}'` with a separately issued
exactly matching permit to receive a numeric result.

## 4. Use an existing MCP host instead of the one-shot CLI

An AI agent framework that supports **stdio MCP servers** may launch:

```json
{
  "command": "shards-kernel",
  "args": ["mcp-relay", "--port", "8765"]
}
```

**Supply `SHARDS_KERNEL_AGENT_TOKEN` securely through the MCP host's secret
manager; do not put its value into the JSON, chat, a command argument or
repository.** Each independent agent needs a separate process and separate
credential. Invoke the discovered tool `governed_execute` with exact
`name`, `arguments` and independently signed `permit` object. The
operator, not the agent label, determines the authenticated principal.

## 5. Acceptance and release boundaries

For reproducible evidence from the source checkout:

```bash
python -m pip install -e ".[dev,crypto,mcp]"
pytest -q tests/test_mcp_agent_relay.py tests/test_mcp_call_cli.py
pytest -q tests/test_operator_process_restart.py
```

The separately reviewed mandatory multi-process security release gate is
implemented by PR #88; its integration and publication gate must pass
independently before a tagged release. Package installability and an agent
MCP tool call are **not** the same thing as remote production certification.

**Out of scope in this release:** remote Streamable HTTP MCP Gateway, wallets,
DEXs, finance, background jobs, arbitrary tools, cloud deployment, KMS/HSM,
multi-replica transactions, externally sealed audit history, public agent
registration, SLA guarantees. These remain separately tracked. Never
reuse another Shards project's database, service, credentials or deployment
when those components are later added.
