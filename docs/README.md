# Shards-Kernel Docs

Documentation for understanding and integrating Shards-Kernel.

## Contents

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component boundaries and data flows |
| [architecture/KERNEL_STRATA.md](architecture/KERNEL_STRATA.md) | Taxonomy for memory/runtime/governance/multi-agent kernel layers |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Adversary model + mitigations |
| [pipelines/HPC_CICD_ARCHITECTURE.md](pipelines/HPC_CICD_ARCHITECTURE.md) | Advanced CI/CD design for deterministic kernel infrastructure |
| [FAQ.md](FAQ.md) | Usage clarifications and non-goals |

## Getting Started

If you need to integrate Shards-Kernel:

1. Start at the main [README.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/README.md) for overview
2. Read [spec/README.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/spec/README.md) for normative requirements
3. Review [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details
4. Check [FAQ.md](FAQ.md) for common questions

## Agent skills (optional, task-specific)

Repository-scoped skills in `.github/skills/<skill-name>/SKILL.md` follow
the standard Agent Skills frontmatter format. They are **instructions
only**, not executable permissions, signed permits or MCP gateways. Agents
and editors with compatible skill discovery can load them on demand; other
clients may need to point to the files explicitly. The concise [AGENTS.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/AGENTS.md)
explains which to choose.

| Skill | Use case |
| --- | --- |
| [get-started](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/get-started/SKILL.md) | Zero-secret install, offline demo and `doctor` |
| [governed-mcp-agent](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/governed-mcp-agent/SKILL.md) | Existing official MCP v2 local stdio relay and signed-permit client |
| [operator-provisioning](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/operator-provisioning/SKILL.md) | Operator policy, separated issuer/approver and audit custody |
| [release-verification](https://github.com/Shards-foundation/Shards-kernel/blob/main/.github/skills/release-verification/SKILL.md) | Exact-commit checks, independent review, branch protections and acceptance |

These replace **neither** the existing trusted operator documentation
**nor** the legacy GPU optimisation `skills/*.md` prompt notes. Their
metadata, local cross-references and security boundaries are checked by
`tests/test_agent_skills.py` in normal CI.

## Relationship to Spec

The `/spec` directory contains **normative** requirements. This `/docs` directory contains **informative** guidance. If they conflict, spec wins.
