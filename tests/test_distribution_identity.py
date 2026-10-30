"""Distribution metadata, entrypoint, and import namespace regression tests."""

import importlib
import subprocess
import sys
from importlib.metadata import distribution


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
