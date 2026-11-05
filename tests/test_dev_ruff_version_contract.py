"""Ensure the selected development linter matches the reproducible project pin."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re

import pytest


PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_installed_ruff_matches_project_dev_pin():
    text = PYPROJECT.read_text(encoding="utf-8")
    pins = re.findall(r'(?m)^\s*"ruff==([0-9][^"]*)"\s*,', text)
    assert len(pins) == 1, "Development tooling must specify exactly one Ruff pin"
    try:
        installed = version("ruff")
    except PackageNotFoundError:
        pytest.skip("Ruff is not installed; install the project's dev extra")
    assert installed == pins[0]
