# Migrating to Shards-Kernel

The repository is **Shards-foundation/Shards-kernel**, the Python distribution is **shards-kernel**, the import namespace is **shards_kernel**, and the command is **shards-kernel**.

The historical `kernels` Python namespace is intentionally **not** installed as a compatibility alias: the PyPI distribution named `kernels` is maintained by a different organisation. Shipping both under the same top-level import namespace would create a package collision.

## Required consumer updates

| Before | After |
| --- | --- |
| `from kernels import StrictKernel` | `from shards_kernel import StrictKernel` |
| `from kernels.api import KernelRequest` | `from shards_kernel.api import KernelRequest` |
| `python -m kernels --help` | `python -m shards_kernel --help` |
| `kernels --version` | `shards-kernel --version` |
| `https://github.com/Shards-foundation/kernels` | `https://github.com/Shards-foundation/Shards-kernel` |

Shards-Kernel's implementation and API names such as `KernelRequest` remain unchanged; only its Python module namespace and distribution tooling change. Consumers referring to internal submodules must update their import paths, although internal submodules are not part of the stable public contract.

## Install and verify

The initial version is published on PyPI. For a released installation:

```bash
python -m pip install "shards-kernel==0.1.2"
python -c "from shards_kernel import StrictKernel; print(StrictKernel)"
python -m shards_kernel --version
shards-kernel --help
```

For a development checkout:

```bash
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel
python -m pip install -e ".[dev]"
python -c "from shards_kernel import StrictKernel; print(StrictKernel)"
python -m shards_kernel --version
shards-kernel --help
python -m pytest tests/test_distribution_identity.py
python -m build
```

The historical `0.1.1` release remains available on PyPI. Version `0.1.2` carries the updated README metadata once the patch release is published. The separate `.github/workflows/publish.yml` workflow publishes verified GitHub release artifacts using OIDC Trusted Publishing; `.github/workflows/release.yml` remains a build-and-verification workflow. PyPI release metadata is immutable after publication, so a future metadata change requires a new release version.

## Integration caveat

Existing environments using the obsolete `kernels` import must migrate before upgrading to this branch. Do not add an import alias named `kernels` to the published wheel; doing so risks interfering with Hugging Face's package.
