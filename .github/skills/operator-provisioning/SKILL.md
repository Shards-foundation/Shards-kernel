---
name: operator-provisioning
description: Prepare Shards-Kernel's independently trusted local operator, agent identity enrollment, signed operator policy, and offline human approval/permit issuance. Use for operator runbooks or security reviews; never automate private-key access or bypass human approval.
license: MIT
---

# Trusted operator and issuer provisioning

**Trust boundary:** this skill guides a trusted operator. It does not grant an AI agent permission to sign permits, read private keys, administer secrets or approve its own requests. For a first-run demonstration without secrets, use [get-started](../get-started/SKILL.md) instead.

## Separate principals and storage

Distinguish five roles:

| Role | Holds | Must not hold |
| --- | --- | --- |
| Human approver | Review authority and separately secured approval signer | Agent bearer; execution privileges |
| Offline permit issuer | Distinct Ed25519 permit-signing key; verified human approval | Agent bearer; shared operator process identity |
| Operator-policy issuer | Distinct policy-signing key; signed v2 policy revisions | Agent-run tool context |
| Local operator process | Public verifier keys; pinned signed policy; private single-host SQLite ledger; operator API key and auth pepper | Any permit/policy private signer |
| Enrolled agent | Its **own** token and previously issued scoped permit | Operator API key, signing keys, peer agent tokens |

Don't collapse any of these roles to make onboarding faster. Do not copy an actual production secret into a prompt, repository, command-line argument, shell trace or sample config. The issuer `--key-fd` is a **pre-opened file descriptor** provided by a trusted external launcher; never replace it with a PEM string in CLI arguments.

## Reviewable operator sequence

1. Confirm Shards-Kernel's exact version/SHA and the intended *local* profile; check the [operator preflight](../../../docs/operations/OPERATOR_PREFLIGHT.md). The `service` profile may correctly be **NOT_READY** even when a signed local operator runs.
2. Determine a dedicated absolute private filesystem path for the signed policy and SQLite ledger under **Shards-Kernel's own** storage. No cross-project sharing of database, credentials, signing authorities, monitoring projects or host.
3. The trusted signer, **outside the agent process**, signs the operator-policy v2 document with a monotonic revision, kernel identity, agent-specific scrypt verifiers and minimal built-in tool allowlists. The operator pins the matching signing **public** key independently. No wildcard agent or arbitrary tool rights.
4. The trusted operator injects `SHARDS_KERNEL_API_KEY`, `SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX` and `SHARDS_KERNEL_AGENT_AUTH_PEPPER` through a private secret manager into the **operator only**. The agent receives only its own `SHARDS_KERNEL_AGENT_TOKEN`.
5. Start `shards-kernel serve --config /absolute/path/to/signed-v2-operator.json`. No `--allow-unsigned-local` outside a disposable development-only demonstration. The loopback operator is **not** an externally available MCP server.
6. For every execution, the **human approver** reviews an exact unsigned permit draft. The distinct issuer verifies that independent approval and signs only the matching one-use `echo`/`add` permit, with a short validity window and correct actor, parameters and kernel audience. No model may self-approve.
7. Supply the issued permit securely to the enrolled client, then use [governed-mcp-agent](../governed-mcp-agent/SKILL.md) to verify ALLOW, DENY, replay refusal and audit continuity.

For issuer commands and a worked *reference* process follow [offline issuer](../../../docs/operations/OFFLINE_ISSUER.md), [signed local operator](../../../docs/operations/LOOPBACK_OPERATOR_SERVICE.md), and [two-agent enrollment](../../../docs/operations/TWO_AGENT_IDENTITY.md). These documents define the exact fields; **do not invent schemas** from an example in a chat.

## Checkpoint and recovery constraints

- Treat policy expiry, missing trusted checkpoint, bad signature, revision rollback, duplicate key, replaced SQLite state, or mismatched actor as **stop conditions**, not warnings.
- Keep the local SQLite audit/replay ledger private and single-host; a process restart with the **same** database must still reject used permits.
- The local SQLite high-water mark is **not an externally anchored trust root**. Database and policy restored together can defeat purely local rollback checks. Document this explicitly.
- Cryptographic key custody, external checkpoint sealing, verified secure backups, process/host isolation and production rollout remain separate security gates.
- This guide never authorizes real trading, wallet signing, external tools, remote forwarding, paid cloud resources or production credentials.

## Report to the next trusted person

Record versions, SHA, policy revision, agent labels (no bearer values), approved tool names, signed policy fingerprint where safe, SQLite health, acceptance results, and external blockers. If issuer custody or human approval is not independently verifiable, report **BLOCKED**. No "temporarily allow all" fallback.

Test-only references: `pytest -q tests/test_mcp_agent_relay.py tests/test_separate_issuer_process_e2e.py tests/test_operator_process_restart.py`.
