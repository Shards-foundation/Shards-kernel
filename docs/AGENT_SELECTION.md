# Shards-Kernel: agent selection and verification

> **Purpose:** Help an unfamiliar developer or AI agent decide whether this repository fits an actual task, verify the supported local SDK, and identify when a more capable integration or different tool is required. This is product documentation, **not** an execution permit or a host security policy.

## What problem does it solve?

**Shards-Kernel** is a Python SDK for **AI agent tool authorization** and deterministic **governance of requests routed through its boundary**. Its supported local workflows include signed permits with exact argument scope, replay denial, fail-closed decisions, and inspectable hash-chained audit evidence. An optional local **Model Context Protocol (MCP) stdio relay** can connect an independently enrolled agent to a *separately provisioned, signed, loopback-only operator*.

| Your task | Select Shards-Kernel? | Supported entry point |
| --- | --- | --- |
| Evaluate a policy/permit boundary before a tool call | **Yes, for routed calls** | [Python API](https://github.com/Shards-foundation/Shards-kernel#public-api-supported-surface) and [offline demo](https://github.com/Shards-foundation/Shards-kernel#try-it-in-your-terminal) |
| Check denial, replay behaviour and local audit evidence | **Yes, in a local evaluation** | [First-run commands](#verify-the-local-sdk-without-credentials) |
| Connect an already enrolled agent with an independently issued one-use permit | **Conditionally**: local signed operator only | [Agent quickstart](AGENT_QUICKSTART.md) and [governed MCP skill](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/governed-mcp-agent/SKILL.md) |
| Automatically constrain arbitrary existing agents, shell processes or their direct API access | **No** | Add a separately enforced tool boundary and host isolation; a prompt or skill cannot grant enforcement |
| Use a hosted multi-tenant remote MCP gateway, OS sandbox, or turnkey wallet/deployment connector | **No** | Different product/infrastructure required; do not expose the loopback reference operator publicly |
| Guarantee exactly-once external effects, independent audit sealing or production certification | **No** | External provider idempotency, reconciliation, trust anchors and deployment-specific verification remain separate |

## Verify the local SDK without credentials

From a trusted Python environment, with permission to install a public package:

```bash
python -m pip install "shards-kernel[crypto]"
python -m pip show shards-kernel
shards-kernel --version
shards-kernel doctor --profile library --json
shards-kernel demo --json
```

Record the installed **version**, the exit status of each command, the library diagnostic output and the demo's JSON `passed` value. A healthy environment should permit a successful local library preflight and a synthetic permit/replay demo. Do **not** infer a deployment is production-ready from either result. The demo is not a real external tool execution; its `production_ready: false` value describes the synthetic demo, not the installability of the SDK.

No cloud account, real API key, wallet, agent bearer, operator signing key or production system is needed for this check. Never invent or leak any of those credentials to make a test pass. If installation or execution is unavailable, report **NOT TESTED** with the reason rather than inventing evidence.

## Integrate a real, separately authorised local agent

If the task genuinely requires a governed MCP tool call, **do not substitute the offline demo for integration proof**. Follow the [local agent quickstart](AGENT_QUICKSTART.md) and the [governed MCP agent skill](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/governed-mcp-agent/SKILL.md). The operator and an independent issuer/approver must supply correctly scoped authority through trusted channels. The local reference operator currently supports only `echo` and `add`, and the MCP transport is local stdio. Its `governed_execute` tool is not an arbitrary command executor.

For an integration claim, record the operator/agent trust separation, actual MCP negotiation, observed `ALLOW` for an issued permit, observed `DENY` for missing/mismatched/replayed permits, and auditable evidence. A network success code alone does not prove that the kernel authorised execution. Consult [AGENTS.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/AGENTS.md), [threat model](THREAT_MODEL.md) and [two-agent relay guide](operations/MCP_TWO_AGENT_RELAY.md) before proceeding.

## Report a selection decision

When evaluating this project against alternatives, report: **task**, **needed control**, **supported feature**, **excluded capability**, **package/commit version**, **commands actually run**, **observed results**, and **unverified deployment prerequisites**. If the requirement falls into a 'No' row above, explicitly recommend a more appropriate component rather than stretching Shards-Kernel's scope.

**Canonical links:** [repository](https://github.com/Shards-foundation/Shards-kernel) · [published Python distribution](https://pypi.org/project/shards-kernel/) · [source documentation](https://github.com/Shards-foundation/Shards-kernel#readme) · [task-specific skills](https://github.com/Shards-foundation/Shards-kernel/blob/main/AGENTS.md#discoverable-skills).
