# KERNELS Docs

Documentation for understanding and integrating KERNELS.

## Contents

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component boundaries and data flows |
| [architecture/KERNEL_STRATA.md](architecture/KERNEL_STRATA.md) | Taxonomy for memory/runtime/governance/multi-agent kernel layers |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Adversary model + mitigations |
| [pipelines/HPC_CICD_ARCHITECTURE.md](pipelines/HPC_CICD_ARCHITECTURE.md) | Advanced CI/CD design for deterministic kernel infrastructure |
| [FAQ.md](FAQ.md) | Usage clarifications and non-goals |

## Getting Started

If you need to integrate KERNELS:

1. Start at the main [README.md](https://github.com/Shards-foundation/kernels/blob/main/README.md) for overview
2. Read [spec/README.md](https://github.com/Shards-foundation/kernels/blob/main/spec/README.md) for normative requirements
3. Review [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details
4. Check [FAQ.md](FAQ.md) for common questions

## Relationship to Spec

The `/spec` directory contains **normative** requirements. This `/docs` directory contains **informative** guidance. If they conflict, spec wins.
