"""Requirements document structural contract.

Keep this dependency-free so both legacy Python CI and Docs CI can enforce it.
This test intentionally catches malformed heading replacements and orphan table rows.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "docs" / "guides" / "REQUIREMENTS.md"
PYPROJECT = ROOT / "pyproject.toml"


class RequirementsDocumentationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = REQUIREMENTS.read_text(encoding="utf-8")
        cls.metadata = PYPROJECT.read_text(encoding="utf-8")

    def test_overview_and_runtime_heading_not_concatenated(self):
        self.assertIn(
            "This document specifies the system requirements for deploying and "
            "operating Shards-Kernel.\n\n## 2. Runtime Requirements\n\n"
            "### 2.1 Python Version\n",
            self.doc,
        )
        self.assertEqual(self.doc.count("### 2.1 Python Version"), 1)
        self.assertIsNotNone(re.search(r"(?m)^### 2\.2 Operating System$", self.doc))

    def test_python_table_has_three_columns_and_no_orphan_rows(self):
        block = self.doc.split("### 2.1 Python Version\n", 1)[1].split(
            "### 2.2 Operating System", 1
        )[0]
        table = [line.strip() for line in block.splitlines() if line.lstrip().startswith("|")]
        self.assertGreaterEqual(len(table), 10)
        self.assertEqual(
            table[0], "| Python | Project compatibility | Upstream Python lifecycle |"
        )
        self.assertRegex(table[1], r"^\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|$")
        for row in table:
            self.assertEqual(row.count("|"), 4, "Malformed Python version row: " + row)
        labels = [row.split("|")[1].strip() for row in table[2:]]
        self.assertEqual(labels, [f"3.{minor}" for minor in range(15, 8, -1)] + ["3.16+"])

    def test_declared_classifiers_match_version_table(self):
        self.assertIn('requires-python = ">=3.9"', self.metadata)
        for minor in range(9, 16):
            self.assertIn(
                f'"Programming Language :: Python :: 3.{minor}"',
                self.metadata,
            )
        self.assertIn(
            "Python 3.9–3.15",
            self.doc,
        )
        self.assertIn("Python 3.11+; older interpreters", self.doc)


if __name__ == "__main__":
    unittest.main()
