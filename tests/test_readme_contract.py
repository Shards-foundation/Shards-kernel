"""Executable contracts for the public README (stdlib-only on Python 3.9+).

These checks defend documentation accuracy. They do not assert that a
remote gateway, hosted service or third-party connector exists.
"""

import ast
import importlib
import importlib.util
import json
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _repository_file(target_url):
    """Map known public GitHub URLs back to the committed local file."""
    prefixes = (
        "https://raw.githubusercontent.com/Shards-foundation/Shards-kernel/main/",
        "https://github.com/Shards-foundation/Shards-kernel/blob/main/",
    )
    prefix = next((item for item in prefixes if target_url.startswith(item)), None)
    if prefix is None:
        raise AssertionError("README target must use a canonical GitHub HTTPS URL")
    target = Path(target_url[len(prefix):])
    if target.is_absolute() or ".." in target.parts or not target.parts:
        raise AssertionError("README target must be a repository-local path")
    resolved = (ROOT / target).resolve()
    if ROOT not in resolved.parents:
        raise AssertionError("README target resolves outside the repository")
    return resolved


def _run_cli(*arguments):
    result = subprocess.run(
        [sys.executable, "-m", "shards_kernel", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise AssertionError(
            "Documented CLI failed: {} (exit {})\n{}".format(
                " ".join(arguments), result.returncode, result.stderr
            )
        )
    return result.stdout


class ReadmeDocumentationContractTests(unittest.TestCase):
    def test_banner_path_resolves_to_real_svg(self):
        readme = README.read_text(encoding="utf-8")
        match = re.search(r"!\[Shards-Kernel branded banner:[^\]]+\]\(([^)]+)\)", readme)
        self.assertIsNotNone(match, "README branded image link missing")
        self.assertEqual(
            match.group(1),
            "https://raw.githubusercontent.com/Shards-foundation/"
            "Shards-kernel/main/docs/images/shards-kernel-banner.svg",
        )
        image_path = _repository_file(match.group(1))
        self.assertTrue(image_path.is_file(), str(image_path))
        self.assertEqual(image_path.suffix, ".svg")
        root = ET.parse(image_path).getroot()
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        title = root.find("{http://www.w3.org/2000/svg}title")
        self.assertIsNotNone(title, "SVG should have accessible title")
        self.assertIn("Shards-Kernel", title.text or "")

    def test_mit_badge_links_to_repository_license(self):
        readme = README.read_text(encoding="utf-8")
        match = re.search(
            r"\[!\[License: MIT\]\(https://img\.shields\.io/badge/License-MIT-[^)]+\)\]\(([^)]+)\)",
            readme,
        )
        self.assertIsNotNone(match, "MIT shields.io badge missing")
        self.assertEqual(
            match.group(1),
            "https://github.com/Shards-foundation/Shards-kernel/blob/main/LICENSE",
        )
        license_path = _repository_file(match.group(1))
        self.assertEqual(license_path, ROOT / "LICENSE")
        self.assertTrue(license_path.is_file())
        self.assertTrue(license_path.read_text(encoding="utf-8").startswith("MIT License\n"))

    def test_install_command_and_python_import_match_package_identity(self):
        readme = README.read_text(encoding="utf-8")
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package = importlib.import_module("shards_kernel")
        self.assertTrue(package.__version__.count(".") >= 2)
        self.assertIn('name = "shards-kernel"', project)
        self.assertIn('shards-kernel = "shards_kernel.__main__:main"', project)
        # README intentionally installs the current published version, not an
        # unapproved future release candidate pinned to source metadata.
        self.assertIn('python -m pip install "shards-kernel[crypto]"', readme)
        self.assertIn(
            'python -c "import shards_kernel; print(shards_kernel.__version__)"',
            readme,
        )
        self.assertIn("not `kernels`", readme)
        self.assertTrue(hasattr(package, "StrictKernel"))

    def test_documented_cli_commands_are_supported(self):
        readme = README.read_text(encoding="utf-8")
        for command in (
            "shards-kernel --version",
            "shards-kernel info --variant strict",
            "shards-kernel demo --json",
        ):
            with self.subTest(command=command):
                self.assertIn(command, readme)
        self.assertIn("shards-kernel " + importlib.import_module("shards_kernel").__version__,
                      _run_cli("--version"))
        self.assertIn("Variant: Strict Kernel", _run_cli("info", "--variant", "strict"))
        self.assertIn("--json", _run_cli("demo", "--help"))

    @unittest.skipUnless(
        importlib.util.find_spec("cryptography") is not None,
        "Optional cryptography extra absent; actual demo is tested in quality CI",
    )
    def test_documented_demo_runs_locally_when_crypto_extra_installed(self):
        result = json.loads(_run_cli("demo", "--json"))
        self.assertTrue(result["passed"])
        self.assertEqual(result["demo"], "OFFLINE_ONLY")
        self.assertIs(result["production_ready"], False)

    def test_use_cases_are_not_misrepresented_as_shipped_connectors(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("## When to use Shards-Kernel", readme)
        section = readme.split("## When to use Shards-Kernel", 1)[1].split(
            "\n## ", 1
        )[0].lower()
        for required in (
            "repository maintenance and deployments",
            "external api access",
            "financial or other high-impact operations",
            "multi-agent orchestration",
            "integration use cases",
            "not a claim",
            "signed local reference operator",
            "`echo` and `add`",
            "not** a sandbox",
        ):
            with self.subTest(required=required):
                self.assertIn(required, section)

        # Compare the local operator's actual allowlist to the README rather
        # than treating its text as evidence of a shipped integration.
        service = ast.parse(
            (ROOT / "shards_kernel/cli/service.py").read_text(encoding="utf-8")
        )
        definitions = [
            node.value for node in service.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "_ALLOWED_TOOLS"
                for target in node.targets
            )
        ]
        self.assertEqual(len(definitions), 1)
        initializer = definitions[0]
        self.assertIsInstance(initializer, ast.Call)
        self.assertIsInstance(initializer.func, ast.Name)
        self.assertEqual(initializer.func.id, "frozenset")
        self.assertEqual(set(ast.literal_eval(initializer.args[0])), {"echo", "add"})


if __name__ == "__main__":
    unittest.main()
