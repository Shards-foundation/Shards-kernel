"""Generate and validate a credential-free, wheel-bound release acceptance record.

Exit nonzero for missing results, skips, test failures or wrong distribution.
This gate is intentionally NOT a certification of production deployment.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import sys
import xml.etree.ElementTree as ET


EXPECTED_VERSION = "0.1.3"
PINNED_TAG_SHA = "5f122099d37c241b5388e10ca2b2d65f74840d47"


def generate(folder):
    wheels = list((folder / "wheels").glob("shards_kernel-*.whl"))
    if len(wheels) != 1:
        raise ValueError("Expected exactly one published Shards-Kernel wheel")
    wheel = wheels[0]
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    actual_version = metadata.version("shards-kernel")

    report = folder / "acceptance-junit.xml"
    if not report.exists():
        raise ValueError("Missing pytest JUnit report; acceptance cannot pass")
    root = ET.parse(report).getroot()
    cases = root.findall(".//testcase")
    totals = {
        "tests": len(cases),
        "passed": sum(not list(c.findall("failure")) and not list(c.findall("error"))
                      and not list(c.findall("skipped")) for c in cases),
        "failed": sum(bool(c.findall("failure")) for c in cases),
        "errors": sum(bool(c.findall("error")) for c in cases),
        "skipped": sum(bool(c.findall("skipped")) for c in cases),
    }
    accepted = (
        actual_version == EXPECTED_VERSION
        and totals["tests"] >= 35
        and totals["passed"] == totals["tests"]
        and totals["failed"] == 0
        and totals["errors"] == 0
        and totals["skipped"] == 0
    )
    record = {
        "schema": "shards-published-acceptance-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if accepted else "FAIL",
        "scope": "Published PyPI wheel; isolated Linux + disposable PostgreSQL service",
        "limitations": [
            "Not two-host or production deployment acceptance",
            "No external-provider idempotency, network partition or real failover test",
            "Trusted SQLite reference root is retained only in test process memory",
            "Not an independent security certification",
        ],
        "release_tag": "v0.1.3",
        "release_tag_commit": PINNED_TAG_SHA,
        "installed_distribution_version": actual_version,
        "wheel_filename": wheel.name,
        "wheel_sha256": digest,
        "python_version": platform.python_version(),
        "pytest": totals,
    }
    output = folder / "acceptance.json"
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": record["status"], "tests": totals,
                      "wheel_sha256": digest}, sort_keys=True))
    return accepted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        accepted = generate(args.output_dir)
    except Exception as exc:
        print(f"Acceptance report not verified: {exc}", file=sys.stderr)
        return 1
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
