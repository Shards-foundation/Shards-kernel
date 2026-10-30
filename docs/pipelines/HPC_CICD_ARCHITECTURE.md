# HPC CI/CD Architecture for Shards-Kernel

This document defines a production-grade CI/CD topology for compute-kernel style
repositories where determinism, security, hardware compatibility, and release
repeatability are first-class gates.

## 1) CI/CD Topology

```text
Developer
  -> Pull Request / Push
  -> Layer 1: Pre-commit Validation
  -> Layer 2: Static Analysis
  -> Layer 3: Dependency & Supply Chain
  -> Layer 4: Build Matrix
  -> Layer 5: Kernel Compilation
  -> Layer 6: Test Matrix
  -> Layer 7: Performance
  -> Layer 8: Security
  -> Layer 9: Packaging
  -> Layer 10: Release
```

## 2) Ten-Layer Workflow Catalog (44 Pipelines)

### Layer 1 — Pre-commit Validation

1. lint-python  
2. lint-cpp  
3. format-check  
4. import-order-check  
5. precommit-hooks  
6. commit-message-lint  
7. secrets-scan

**Primary tools:** ruff, black, clang-format, pre-commit, commitlint, gitleaks.

### Layer 2 — Static Code Analysis

8. mypy-type-check  
9. pylint-analysis  
10. code-complexity-check  
11. dead-code-detection  
12. docstring-coverage  
13. codeql-analysis

**Primary tools:** mypy, pylint, radon, vulture, codeql.

### Layer 3 — Dependency & Supply Chain

14. dependency-vulnerability-scan  
15. license-compliance  
16. dependency-update-check  
17. sbom-generation

**Primary tools:** pip-audit, safety, syft, dependabot.

### Layer 4 — Build Matrix

18. build-linux  
19. build-macos  
20. build-python-3.9  
21. build-python-3.10  
22. build-python-3.11  
23. build-cuda-11  
24. build-cuda-12

### Layer 5 — Kernel Compilation

25. compile-cuda-kernels  
26. compile-cpu-kernels  
27. compile-ptx  
28. compile-avx-optimizations

### Layer 6 — Testing

29. unit-tests  
30. integration-tests  
31. api-contract-tests  
32. gpu-runtime-tests  
33. numerical-accuracy-tests  
34. memory-safety-tests

**Primary tools:** pytest, cuda-memcheck, ASAN, valgrind.

### Layer 7 — Performance

35. benchmark-kernels  
36. performance-regression-detection  
37. latency-analysis  
38. memory-bandwidth-tests

**Primary tools:** pytest-benchmark, nvprof, Nsight Systems, Nsight Compute, Airspeed Velocity.

### Layer 8 — Security

39. container-vulnerability-scan  
40. binary-vulnerability-scan  
41. fuzz-testing

**Primary tools:** trivy, grype, libFuzzer, hypothesis.

### Layer 9 — Packaging

42. build-python-wheels  
43. build-docker-images

### Layer 10 — Release

44. publish-release

**Primary outputs:** signed PyPI wheels, signed OCI images, compiled kernels,
benchmark reports, SBOM + provenance attestations.

## 3) Repository Layout Recommendation

```text
repo/
├── shards_kernel/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── gpu/
│   └── benchmarks/
├── benchmarks/
├── docker/
├── scripts/
├── .github/workflows/
└── pyproject.toml
```

## 4) Shards-Kernel Workflow Mapping

The following files in this repository implement core parts of the architecture. `.github/workflows/hpc-matrix.yml`, `.github/workflows/gpu-hardware.yml`, and `.github/workflows/benchmark.yml` are not in this repository.

| Existing workflow | Layer coverage | Notes |
|---|---|---|
| `.github/workflows/ci.yml` | 1, 2, 4, 6 | Fast lint/type/test/build gate |
| `.github/workflows/security.yml` | 1, 2, 3, 8 | CodeQL, dependency review, secret scanning |
| `.github/workflows/dependency-health.yml` | 3 | Dependency graph and vulnerability health |
| `.github/workflows/dependency-canary.yml` | 3, 4 | Canary runs against latest dependencies |
| `.github/workflows/release.yml` | 9, 10 | Build + publish releases |
| `.github/workflows/docs.yml` | release support | Documentation validation and publication |

## 5) Performance Regression Gate

Use artifact-backed baseline comparison:

1. Store a baseline benchmark artifact from `main`.
2. Run PR benchmarks on the same hardware class.
3. Compare with a fixed threshold (default: 5% slowdown).
4. Fail PR when threshold is exceeded.

The 5% slowdown value is intended as a conservative default that works well for many
numerical and GPU/CPU kernel workloads where benchmark noise is typically low but
non-zero. Projects SHOULD tune this threshold based on:

- The inherent variance of each benchmark (e.g., noisy integration tests may need a higher tolerance).
- The business and latency criticality of the kernel (e.g., low-latency paths may warrant a stricter threshold).
- The stability of the underlying hardware and environment (e.g., shared/cloud GPUs vs. dedicated machines).

In practice, configure the threshold as a parameter in your CI (per-suite or per-benchmark)
rather than hard-coding 5% globally, and document the chosen values and rationale in
the repository (e.g., in `CONTRIBUTING.md` or a benchmarking README).

## 6) Hardware Validation Strategy

Recommended dedicated GPU runner pools:

- Self-hosted RTX 4090
- Self-hosted A100
- Self-hosted H100

Alternative cloud-backed runner pools:

- RunPod
- Lambda Labs
- GCP GPU nodes

## 7) Scaling Guidance for Large Projects

- Cache aggressively: Python deps, build outputs, ccache, benchmark baselines.
- Shard expensive tests across runners.
- Keep PR checks fast; move deep validation to nightly/release candidates.
- Use reusable workflows to avoid duplication across matrix dimensions.

## 8) Security Hardening Controls

- Signed commits + signed tags.
- SBOM generation per build.
- Artifact signing with Sigstore/Cosign.
- SLSA provenance attestations for release bundles.

## 9) Coverage Policy

Recommended minimum gate:

```bash
pytest --cov=kernels --cov-fail-under=85
```

Raise the threshold for critical packages over time as flaky suites are removed.

## 10) Advanced Optional Pipelines

For kernel-heavy production systems, add:

- Kernel fuzzing
- PTX verification
- ABI compatibility tests
- GPU driver compatibility matrix
- Binary reproducibility checks
