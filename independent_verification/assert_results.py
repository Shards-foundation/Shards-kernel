"""Classify raw observations separately from the probe process.

Do not suppress known violations to obtain green CI.
"""
import json
import os
from pathlib import Path

data = json.loads(Path(os.environ.get("CERT_OUTPUT", "independent-results.json")).read_text())
probes = {p.get("id"): p for p in data["probes"]}
issues = []
for name in ("SK-001", "SK-002", "SK-003"):
    if name not in probes or "harness_error" in probes[name]:
        issues.append("HARNESS_INCOMPLETE: " + name)
if "SK-002" in probes:
    cases = probes["SK-002"]["cases"]
    if cases[0]["decision"] != "ALLOW" or not cases[0]["effects"]:
        issues.append("INVALID_POSITIVE_CONTROL: SK-002")
    if probes["SK-002"]["omission_executed"]:
        issues.append("SK-002: omitted signed permit parameters executed")
if "SK-001" in probes:
    for c in probes["SK-001"]["cases"]:
        if c["overconsumed"]:
            issues.append("SK-001: permit overconsumption at limit " + str(c["limit"]))
        if c["exceptions"]:
            issues.append("SK-001: uncontrolled exceptions at limit " + str(c["limit"]))
if "SK-003" in probes:
    for c in probes["SK-003"]["cases"]:
        if not c["valid_crash"]:
            issues.append("SK-003: crash experiment invalid in " + c["mode"])
        if c["mode"] == "sqlite" and c["effects_after_retry"] > 1:
            issues.append("SK-003: durable intent did not prevent duplicate external effect")
        if c["mode"] == "memory" and c["effects_after_retry"] > 1:
            print("EXPECTED_LIMITATION: in-memory kernel cannot recover after process crash")
print(json.dumps({"findings": issues}, indent=2))
raise SystemExit(1 if issues else 0)
