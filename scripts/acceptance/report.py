"""Fail-closed v0.1.3 wheel acceptance receipt (NOT production certification).

Always creates a machine-readable PASS or FAIL record, including missing-JUnit
and setup-failure paths. Source/release identities are pinned by the workflow.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import sys

try:
    from defusedxml import ElementTree as ET
except ImportError:
    # When setup fails before dependencies install, still emit a FAIL JSON receipt.
    ET = None

EXPECTED_VERSION = "0.1.3"
PINNED_TAG_SHA = "5f122099d37c241b5388e10ca2b2d65f74840d47"
EXPECTED_WHEEL_SHA256 = "baf246e771ceb559d007efafbe8ba66099bd8a65d488ca60294cae5313278df9"
STAGED_FILES = (
    "acceptance_local.py",
    "acceptance_postgres.py",
    "test_distributed_postgres_accounting.py",
    "test_distributed_kernel_execution.py",
    "conftest.py",
)
EXPECTED_CASES = frozenset({
    ("test_distributed_postgres_accounting", "test_single_use_and_no_tentative_intent_left_on_denial"),
    ("test_distributed_postgres_accounting", "test_distinct_hosts_compete_for_one_global_use"),
    ("test_distributed_postgres_accounting", "test_multi_use_budget_and_same_operation_never_double_charges"),
    ("test_distributed_postgres_accounting", "test_nonce_collision_is_fail_closed_and_not_spent"),
    ("test_distributed_postgres_accounting", "test_ambiguous_external_effect_requires_reconciliation"),
    ("test_distributed_postgres_accounting", "test_reserved_does_not_claim_external_success"),
    ("test_distributed_postgres_accounting", "test_partition_and_validation_fail_closed"),
    ("test_distributed_postgres_accounting", "test_identifier_and_public_api_input_boundaries"),
    ("test_distributed_postgres_accounting", "test_all_recovery_operations_fail_closed_when_primary_unreachable"),
    ("test_distributed_postgres_accounting", "test_remaining_contract_and_transition_guards"),
    ("test_distributed_kernel_execution", "test_enable_is_explicit_preboot_and_requires_postgres"),
    ("test_distributed_kernel_execution", "test_single_global_permit_cannot_execute_on_two_kernels"),
    ("test_distributed_kernel_execution", "test_bad_signature_denied_before_budget_consumption"),
    ("test_distributed_kernel_execution", "test_tool_registry_substitution_denied_before_reservation"),
    ("test_distributed_kernel_execution", "test_primary_outage_halts_before_dispatch"),
    ("test_distributed_kernel_execution", "test_crash_after_global_reservation_before_local_intent_stays_reserved"),
    ("test_distributed_kernel_execution", "test_uncertain_execution_is_not_retried_automatically"),
    ("test_distributed_kernel_execution", "test_shared_primary_is_only_nonce_authority"),
    ("test_distributed_kernel_execution", "test_shared_mode_refuses_insecure_or_non_strict_boot"),
    ("test_distributed_kernel_execution", "test_existing_local_hmac_replay_semantics_unchanged"),
    ("test_distributed_kernel_execution", "test_builtin_add_reconciles_with_audit_hash"),
    ("test_distributed_kernel_execution", "test_rejected_legacy_hmac_never_reserves_global_budget"),
    ("test_distributed_kernel_execution", "test_only_pinned_builtins_can_reach_global_reservation"),
    ("test_distributed_kernel_execution", "test_dispatch_gate_failure_halts_before_tool_effect"),
    ("test_distributed_kernel_execution", "test_failed_builtin_execution_quarantines_unknown"),
    ("test_distributed_kernel_execution", "test_failed_reconciliation_halts_without_releasing_budget"),
    ("test_distributed_kernel_execution", "test_global_strict_admission_boundary_without_database_is_unit_testable"),
    ("test_distributed_kernel_execution", "test_global_strict_budget_denial_is_pre_execution"),
    ("test_distributed_kernel_execution", "test_global_strict_requires_pinned_ed25519_not_legacy_hmac"),
    ("test_distributed_kernel_execution", "test_global_strict_refuses_registry_substitution_with_unit_journal"),
    ("test_distributed_kernel_execution", "test_global_strict_dispatch_and_reconcile_faults_halt_with_unit_journal"),
    ("test_distributed_kernel_execution", "test_global_strict_runtime_failure_marks_unknown_in_unit_journal"),
    ("test_distributed_kernel_execution", "test_global_strict_failed_unknown_transition_halts"),
    ("acceptance_local", "test_published_distribution_is_not_source_checkout"),
    ("acceptance_local", "test_offline_cli_demo_all_seven_invariants"),
    ("acceptance_local", "test_sqlite_recovery_and_modified_entry_refusal"),
    ("acceptance_local", "test_truncation_requires_independently_retained_root"),
    ("acceptance_local", "test_single_instance_20_thread_single_use_budget"),
    ("acceptance_postgres", "test_two_os_processes_share_one_authority"),
    ("acceptance_postgres", "test_crash_retains_budget_and_quarantines_uncertainty[reserved]"),
    ("acceptance_postgres", "test_crash_retains_budget_and_quarantines_uncertainty[dispatched]"),
})
if len(EXPECTED_CASES) != 41:
    raise RuntimeError("Acceptance identity manifest is incomplete")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def distribution_version(package):
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def postgres_server_version():
    import psycopg

    dsn = os.environ.get("SHARDS_TEST_POSTGRES_DSN", "")
    if not dsn:
        return None
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        return str(conn.execute("SHOW server_version").fetchone()[0])


def _safe_json(path):
    if path.stat().st_size > 2_000_000:
        raise ValueError("Oversized manifest")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_junit(path):
    if ET is None:
        raise ValueError("Safe JUnit parser unavailable")
    if path.stat().st_size > 4_000_000:
        raise ValueError("Oversized JUnit XML")
    tree = ET.parse(path)
    cases = tree.getroot().findall(".//testcase")
    keys = []
    counts = {"tests": len(cases), "passed": 0, "failed": 0,
              "errors": 0, "skipped": 0}
    for case in cases:
        name = case.get("name", "")
        classname = case.get("classname", "").split(".")[-1]
        keys.append((classname, name))
        statuses = (
            bool(case.findall("failure")),
            bool(case.findall("error")),
            bool(case.findall("skipped")),
        )
        if any(statuses):
            for status, field in zip(statuses, ("failed", "errors", "skipped")):
                counts[field] += int(status)
        else:
            counts["passed"] += 1
    return keys, counts


def generate(folder):
    """Generate a receipt even when prerequisites or test execution failed."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    issues = []
    record = {
        "schema": "shards-published-acceptance-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "FAIL",
        "scope": "Published v0.1.3 wheel, isolated CI runner, disposable PostgreSQL",
        "limitations": [
            "Not a production or independent security certification",
            "Not a two-host or network-partition acceptance",
            "No external provider effect or independent off-host checkpoint",
            "SQLite reference root is retained in test memory only",
        ],
        "release_tag": "v0.1.3",
        "release_tag_commit": PINNED_TAG_SHA,
        "expected_wheel_sha256": EXPECTED_WHEEL_SHA256,
        "wheel_sha256": None,
        "wheel_filename": None,
        "harness_commit": None,
        "staged_test_sha256": {},
        "python_version": platform.python_version(),
        "operating_system": platform.platform(),
        "postgres_service_image": "postgres:16",
        "postgres_server_version": None,
        "installed_distribution_version": None,
        "pytest_exit_code": None,
        "pytest": {"tests": 0, "passed": 0, "failed": 0,
                   "errors": 0, "skipped": 0},
        "missing_cases": [],
        "unexpected_cases": [],
        "dependencies": {},
        "failures": [],
    }

    wheels = list((folder / "wheels").glob("shards_kernel-*.whl"))
    if len(wheels) != 1:
        issues.append("MISSING_OR_MULTIPLE_WHEELS")
    else:
        wheel = wheels[0]
        record["wheel_filename"] = wheel.name
        try:
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            record["wheel_sha256"] = digest
            if digest != EXPECTED_WHEEL_SHA256:
                issues.append("PUBLISHED_WHEEL_HASH_MISMATCH")
        except OSError:
            issues.append("WHEEL_READ_FAILED")

    installed = distribution_version("shards-kernel")
    record["installed_distribution_version"] = installed
    if installed != EXPECTED_VERSION:
        issues.append("INSTALLED_VERSION_MISMATCH")
    for name in ("cryptography", "psycopg", "pytest", "defusedxml"):
        record["dependencies"][name] = distribution_version(name)
        if record["dependencies"][name] is None:
            issues.append("MISSING_DEPENDENCY_" + name.upper())
    try:
        record["postgres_server_version"] = postgres_server_version()
        if not record["postgres_server_version"]:
            issues.append("POSTGRES_VERSION_MISSING")
    except Exception:
        issues.append("POSTGRES_VERSION_UNAVAILABLE")

    status_file = folder / "pytest-exit-code.txt"
    try:
        status_text = status_file.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9]{1,3}", status_text):
            raise ValueError("Invalid status")
        exit_code = int(status_text)
        record["pytest_exit_code"] = exit_code
        if exit_code != 0:
            issues.append("PYTEST_PROCESS_NONZERO")
    except (OSError, ValueError):
        issues.append("PYTEST_EXIT_STATUS_MISSING_OR_INVALID")

    junit = folder / "acceptance-junit.xml"
    try:
        keys, totals = _read_junit(junit)
        record["pytest"] = totals
        actual = set(keys)
        record["missing_cases"] = sorted(
            ".".join(pair) for pair in EXPECTED_CASES - actual
        )
        record["unexpected_cases"] = sorted(
            ".".join(pair) for pair in actual - EXPECTED_CASES
        )
        if (
            len(keys) != len(EXPECTED_CASES)
            or len(actual) != len(keys)
            or actual != EXPECTED_CASES
        ):
            issues.append("TEST_IDENTITY_SET_MISMATCH")
        if totals["failed"] or totals["errors"] or totals["skipped"] or (
            totals["passed"] != len(EXPECTED_CASES)
        ):
            issues.append("PYTEST_INCOMPLETE_OR_FAILED")
    except Exception:
        issues.append("JUNIT_MISSING_OR_INVALID")

    try:
        recorded_head = (folder / "harness-commit.txt").read_text(
            encoding="utf-8"
        ).strip()
        workflow_head = os.environ.get("GITHUB_SHA", "")
        if (
            SHA.fullmatch(recorded_head) is None
            or recorded_head != workflow_head
        ):
            issues.append("HARNESS_COMMIT_UNTRUSTED")
        record["harness_commit"] = recorded_head
    except OSError:
        issues.append("HARNESS_COMMIT_MISSING")

    try:
        manifest = _safe_json(folder / "acceptance-sources.json")
        if (
            set(manifest) != set(STAGED_FILES)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in manifest.values()
            )
        ):
            raise ValueError("Bad manifest")
        for name in STAGED_FILES:
            actual_digest = hashlib.sha256(
                (folder / "shards-acceptance" / name).read_bytes()
            ).hexdigest()
            record["staged_test_sha256"][name] = actual_digest
            if manifest[name] != actual_digest:
                issues.append("STAGED_TEST_HASH_MISMATCH_" + name)
    except (OSError, ValueError, TypeError, AttributeError):
        issues.append("STAGED_SOURCE_MANIFEST_MISSING_OR_INVALID")

    record["failures"] = sorted(set(issues))
    record["status"] = "PASS" if not record["failures"] else "FAIL"
    (folder / "acceptance.json").write_text(
        json.dumps(record, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": record["status"],
        "pytest": record["pytest"],
        "issues": record["failures"],
        "wheel_sha256": record["wheel_sha256"],
    }, sort_keys=True))
    return record["status"] == "PASS"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        return 0 if generate(args.output_dir) else 1
    except Exception as exc:
        # A fatal report-generation failure must never be reported as PASS.
        fallback = {
            "schema": "shards-published-acceptance-v2",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "FAIL",
            "failures": ["REPORT_INTERNAL_ERROR_" + type(exc).__name__],
        }
        try:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / "acceptance.json").write_text(
                json.dumps(fallback, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as write_error:
            # Preserve nonzero exit even if the filesystem cannot store FAIL JSON.
            print(
                "Could not persist FAIL acceptance receipt: "
                + type(write_error).__name__,
                file=sys.stderr,
            )
        print(
            "Acceptance report generation failed: " + type(exc).__name__,
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
