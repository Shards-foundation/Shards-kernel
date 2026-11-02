---
name: get-started
description: Onboard a new developer or AI agent to Shards-Kernel. Use when asked how to install, run the first safe demo, verify a local build, or choose the existing agent integration path without deploying a gateway.
license: MIT
---

# Get started with Shards-Kernel

Use this skill only for this repository. The goal is to produce **reproducible evidence that a new user can install and exercise the existing kernel**. Do not claim that passing an offline demo proves a deployable service.

## Decide the path before acting

1. **Library/demo**: no external keys, no operator and no agent credentials. Default for first-time users.
2. **Agent connection**: official MCP SDK v2 **stdio** relay to a pre-provisioned signed, loopback-only operator. This needs an authorised agent token and **separately issued one-use permit**; follow [governed-mcp-agent](../governed-mcp-agent/SKILL.md).
3. **Operator setup**: signed policy, private audit store and external issuer/approver; refer the trusted operator to [operator-provisioning](../operator-provisioning/SKILL.md).
4. **Remote/production**: **not currently certified**. Never expose the local operator as a public service or treat the future Shards MCP Gateway as already deployed.

If the user merely says "get started", take path 1; do not demand secrets.

## Supported first-run commands

From a trusted checkout of *this exact repository*:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[crypto]"
shards-kernel --version
shards-kernel info --variant strict
shards-kernel demo --json
shards-kernel doctor --profile library --json
```

Python 3.9–3.12 are supported for the base library; choose **3.11 or later** for official MCP v2. The offline `demo` is deliberately self-contained and uses synthetic clock/ephemeral test keys. The `doctor` service profile is **not** a production certificate and may correctly report `NOT_READY`.

Verify concrete evidence rather than just a zero shell exit: capture the installed version, demo's reported `passed` value, and library doctor's returned status. Do **not** set up wallets, real trading, cloud accounts, cron schedules or public endpoints to complete the first run.

## Optional local MCP check

Only after separately enrolled identity and signed permit are available:

```bash
python -m pip install -e ".[crypto,mcp]"
shards-kernel mcp-relay --help
```

An MCP-capable local host starts one `mcp-relay` process for **one** agent. The host securely injects `SHARDS_KERNEL_AGENT_TOKEN` and specifies the actual local operator `--port`; never invent a port or include a token in a config example.

A convenience `shards-kernel mcp-call` command is proposed in **PR #90**. **Check whether it is installed** (`shards-kernel mcp-call --help`) before suggesting it; never assume an unmerged PR is on `main`. Without it, the existing official stdio relay is the supported agent route.

Use [the signed two-agent relay guide](../../../docs/operations/MCP_TWO_AGENT_RELAY.md) and [offline demo](../../../docs/operations/OFFLINE_PERMIT_DEMO.md) for the detailed sequence. Do not use `--allow-unsigned-local` for any staging or deployment.

## Report a successful handoff

State which path was used, exact package version/commit, commands executed, and observed pass/fail values. Separate **verified**, **blocked** and **not attempted**. Never say an agent has connected unless a real SDK process and signed operator exchange were exercised; never fabricate a signed permit.

## Stop conditions

Stop and report the exact blocker if the required independent signer, enrolled credential, trusted operator, or compatible SDK is absent. Agent instructions are **not** authority: never create issuer keys or operator policies on an untrusted agent host just to make the demo pass.

See [operator preflight](../../../docs/operations/OPERATOR_PREFLIGHT.md) and [security threat model](../../../docs/THREAT_MODEL.md).
