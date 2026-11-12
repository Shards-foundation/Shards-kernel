"""Distribution metadata, entrypoint, and import namespace regression tests."""

import importlib
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path


def test_distribution_name_and_version():
    dist = distribution("shards-kernel")
    package = importlib.import_module("shards_kernel")
    assert dist.metadata["Name"].lower().replace("_", "-") == "shards-kernel"
    assert dist.version == package.__version__


def test_public_api_identity():
    package = importlib.import_module("shards_kernel")
    api = importlib.import_module("shards_kernel.api")
    assert package.StrictKernel is api.StrictKernel
    assert package.KernelRequest is api.KernelRequest
    assert package.Decision is api.Decision


def test_entrypoint_metadata():
    dist = distribution("shards-kernel")
    scripts = {entry.name: entry.value for entry in dist.entry_points if entry.group == "console_scripts"}
    assert scripts["shards-kernel"] == "shards_kernel.__main__:main"
    assert "kernels" not in scripts


def test_module_cli_is_invokable():
    result = subprocess.run([sys.executable, "-m", "shards_kernel", "--version"], capture_output=True, text=True, check=True)
    assert result.stdout.strip().startswith("shards-kernel ")


def test_documentation_preserves_canonical_distribution_identity():
    root = Path(__file__).resolve().parents[1]
    guides = (
        "docs/guides/QUICKSTART.md",
        "docs/guides/SETUP.md",
        "docs/PACKAGE_MIGRATION.md",
    )
    # Install instructions must work while the next release is still a
    # candidate and must not claim an unpublished version exists on PyPI.
    install_command = "python -m pip install shards-kernel"
    for relative_path in guides:
        document = (root / relative_path).read_text(encoding="utf-8")
        lines = {line.strip() for line in document.splitlines()}
        assert install_command in lines, relative_path
        assert "python -m pip install shards-kernel==" not in document, relative_path
        assert 'python -m pip install "shards-kernel==' not in document, relative_path
        assert "from shards_kernel import StrictKernel" in document, relative_path
        assert "shards-kernel --help" in document, relative_path
        assert "release is pending" not in document.lower(), relative_path
        assert "pip install kernels" not in document, relative_path
        assert "pip uninstall kernels" not in document, relative_path

    migration = (root / "docs/PACKAGE_MIGRATION.md").read_text(encoding="utf-8")
    assert "\x60from kernels import StrictKernel\x60 | \x60from shards_kernel import StrictKernel\x60" in migration
    assert "Do not add an import alias named \x60kernels\x60" in migration
    assert "publish.yml\x60 workflow publishes verified GitHub release artifacts using OIDC Trusted Publishing" in migration
    assert "release.yml\x60 remains a build-and-verification workflow" in migration
