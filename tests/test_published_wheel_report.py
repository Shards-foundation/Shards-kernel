"""Adversarial acceptance-reporter regression tests.

No published package installation, live database, or network is required.
Synthetic evidence verifies failures cannot be labelled PASS.
"""

import hashlib
import json
from xml.etree import ElementTree as Writer

import pytest

from scripts.acceptance import report


def make_junit(folder, cases, result=None):
    root = Writer.Element("testsuite")
    for index, (module, name) in enumerate(cases):
        case = Writer.SubElement(root, "testcase", classname=module, name=name)
        if result and index == 0:
            Writer.SubElement(case, result).text = "synthetic negative test"
    Writer.ElementTree(root).write(
        folder / "acceptance-junit.xml", encoding="utf-8", xml_declaration=True
    )


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    """Construct a complete synthetic 41-case report envelope."""
    versions = {
        "shards-kernel": "0.1.3",
        "cryptography": "48.0.1",
        "psycopg": "3.3.8",
        "pytest": "9.2.0",
        "defusedxml": "0.7.1",
    }
    monkeypatch.setattr(report, "distribution_version", versions.get)
    monkeypatch.setattr(report, "postgres_server_version", lambda: "16.15")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    wheel_bytes = b"synthetic-wheel-not-a-real-package"
    (wheel_dir / "shards_kernel-0.1.3-py3-none-any.whl").write_bytes(wheel_bytes)
    monkeypatch.setattr(
        report, "EXPECTED_WHEEL_SHA256",
        hashlib.sha256(wheel_bytes).hexdigest(),
    )
    (tmp_path / "harness-commit.txt").write_text("a" * 40)
    (tmp_path / "pytest-exit-code.txt").write_text("0\n")
    staged = tmp_path / "shards-acceptance"
    staged.mkdir()
    manifest = {}
    for name in report.STAGED_FILES:
        content = ("test-source:" + name).encode("utf-8")
        (staged / name).write_bytes(content)
        manifest[name] = hashlib.sha256(content).hexdigest()
    (tmp_path / "acceptance-sources.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    make_junit(tmp_path, sorted(report.EXPECTED_CASES))
    return tmp_path, versions


def inspect(folder):
    verified = report.generate(folder)
    payload = json.loads((folder / "acceptance.json").read_text())
    return verified, payload


def test_complete_exact_suite_reports_pass(evidence):
    folder, _ = evidence
    valid, receipt = inspect(folder)
    assert valid is True
    assert receipt["status"] == "PASS"
    assert receipt["pytest"]["tests"] == 41
    assert len(receipt["staged_test_sha256"]) == len(report.STAGED_FILES)


@pytest.mark.parametrize("mode", ["dropped", "substituted", "duplicated"])
def test_test_identity_is_not_a_count_threshold(evidence, mode):
    folder, _ = evidence
    cases = sorted(report.EXPECTED_CASES)
    if mode == "dropped":
        cases.pop(0)
    elif mode == "substituted":
        cases[0] = ("acceptance_local", "test_unrelated_claim")
    else:
        cases[0] = cases[1]
    make_junit(folder, cases)
    valid, record = inspect(folder)
    assert valid is False
    assert "TEST_IDENTITY_SET_MISMATCH" in record["failures"]


@pytest.mark.parametrize("status", ["failure", "error", "skipped"])
def test_failed_or_skipped_junit_fails(evidence, status):
    folder, _ = evidence
    make_junit(folder, sorted(report.EXPECTED_CASES), result=status)
    valid, record = inspect(folder)
    assert not valid
    assert record["status"] == "FAIL"
    assert "PYTEST_INCOMPLETE_OR_FAILED" in record["failures"]


@pytest.mark.parametrize("exit_code", ["1", "2", "123", "not-a-code"])
def test_pytest_process_status_is_required(evidence, exit_code):
    folder, _ = evidence
    (folder / "pytest-exit-code.txt").write_text(exit_code)
    valid, record = inspect(folder)
    assert not valid
    assert any("PYTEST" in item for item in record["failures"])


def test_missing_junit_still_writes_machine_readable_failure(evidence):
    folder, _ = evidence
    (folder / "acceptance-junit.xml").unlink()
    valid, record = inspect(folder)
    assert not valid
    assert record["status"] == "FAIL"
    assert "JUNIT_MISSING_OR_INVALID" in record["failures"]


def test_missing_wheel_still_writes_failure_record(evidence):
    folder, _ = evidence
    for wheel in (folder / "wheels").iterdir():
        wheel.unlink()
    valid, record = inspect(folder)
    assert not valid
    assert record["wheel_sha256"] is None
    assert "MISSING_OR_MULTIPLE_WHEELS" in record["failures"]


def test_published_wheel_hash_is_pinned(evidence):
    folder, _ = evidence
    (folder / "wheels" / "shards_kernel-0.1.3-py3-none-any.whl").write_bytes(b"different")
    valid, record = inspect(folder)
    assert not valid
    assert "PUBLISHED_WHEEL_HASH_MISMATCH" in record["failures"]


def test_mismatched_installed_version_is_rejected(evidence, monkeypatch):
    folder, versions = evidence
    versions["shards-kernel"] = "0.1.2"
    valid, record = inspect(folder)
    assert not valid
    assert "INSTALLED_VERSION_MISMATCH" in record["failures"]


def test_missing_harness_commit_or_mismatch_is_rejected(evidence):
    folder, _ = evidence
    (folder / "harness-commit.txt").write_text("b" * 40)
    valid, record = inspect(folder)
    assert not valid
    assert "HARNESS_COMMIT_UNTRUSTED" in record["failures"]


def test_tampered_staged_source_is_rejected(evidence):
    folder, _ = evidence
    (folder / "shards-acceptance" / "acceptance_local.py").write_text("unexpected")
    valid, record = inspect(folder)
    assert not valid
    assert "STAGED_TEST_HASH_MISMATCH_acceptance_local.py" in record["failures"]


def test_missing_source_manifest_is_rejected(evidence):
    folder, _ = evidence
    (folder / "acceptance-sources.json").unlink()
    valid, record = inspect(folder)
    assert not valid
    assert "STAGED_SOURCE_MANIFEST_MISSING_OR_INVALID" in record["failures"]


def test_dtd_payload_is_not_interpreted_as_valid_junit(evidence):
    folder, _ = evidence
    (folder / "acceptance-junit.xml").write_text(
        '<!DOCTYPE x [<!ENTITY x "evil">]><testsuite><testcase name="&x;" /></testsuite>'
    )
    valid, record = inspect(folder)
    assert not valid
    assert "JUNIT_MISSING_OR_INVALID" in record["failures"]
