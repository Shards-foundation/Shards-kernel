"""Read-only, fail-loud Shards-Kernel operator environment diagnostics.

The command performs *preflight* checks. It cannot certify a deployed service,
issuer, persistent ledger, network ingress or multi-agent identity.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any

from shards_kernel._version import __version__
from shards_kernel.common.time import ClockRollbackError, SystemClock


def diagnose(
    profile: str = "service",
    *,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a credential-redacted diagnostic report."""
    if profile not in {"service", "library"}:
        raise ValueError("profile must be 'service' or 'library'")
    env = os.environ if environ is None else environ
    checks: list[dict[str, str]] = []

    def record(check_id: str, status: str, detail: str) -> None:
        checks.append({"id": check_id, "status": status, "detail": detail})

    supported = sys.version_info >= (3, 9)
    record(
        "python",
        "PASS" if supported else "BLOCKED",
        "Supported Python runtime detected" if supported else "Python 3.9+ required",
    )
    try:
        clock = SystemClock()
        first = clock.now_ms()
        second = clock.now_ms()
        if second < first:
            raise ClockRollbackError("Clock moved backwards")
        record("clock_primitive", "PASS", "SystemClock monotonic-in-process probe passed")
    except ClockRollbackError:
        record("clock_primitive", "BLOCKED", "SystemClock probe failed; do not issue permits")

    if profile == "service":
        crypto = importlib.util.find_spec("cryptography") is not None
        record(
            "ed25519_library",
            "PASS" if crypto else "BLOCKED",
            "Ed25519 cryptography dependency installed"
            if crypto else "Install shards-kernel[crypto] for public-only permit verification",
        )
        mcp = sys.version_info >= (3, 11) and importlib.util.find_spec("mcp") is not None
        record(
            "mcp_sdk",
            "PASS" if mcp else "BLOCKED",
            "Official local MCP SDK installed"
            if mcp else "Python 3.11+ and shards-kernel[mcp] required for SDK-backed MCP",
        )
        api_key = env.get("SHARDS_KERNEL_API_KEY")
        valid_key = isinstance(api_key, str) and len(api_key) >= 32 and api_key.strip() == api_key
        record(
            "http_credential",
            "PASS" if valid_key else "BLOCKED",
            "HTTP transport key supplied (value redacted)"
            if valid_key else "Missing or invalid SHARDS_KERNEL_API_KEY (never show its value)",
        )
        # These are *runtime* guarantees, not properties of an installed wheel.
        # Do not claim PASS merely because a file or environment variable exists.
        record(
            "trusted_issuer",
            "NOT_VERIFIED",
            "Issuer identity, operator approval and public-key trust policy require runtime evidence",
        )
        record(
            "durable_evidence",
            "NOT_VERIFIED",
            "Audited storage, transactional replay recovery and restore require live verification",
        )
        record(
            "gateway_security",
            "NOT_VERIFIED",
            "Remote agent authentication and TLS ingress require live integration testing",
        )

    ready = all(c["status"] == "PASS" for c in checks)
    return {
        "name": "Shards-Kernel",
        "version": __version__,
        "profile": profile,
        "ready": ready,
        "assessment": "LIBRARY_CHECKS_PASS" if ready else "NOT_READY",
        "checks": checks,
        "scope": "Preflight environment only, not a live deployment certification",
    }


def run_doctor(profile: str = "service", *, json_output: bool = False) -> int:
    """Print diagnostic results and return non-zero for any unverified gate."""
    report = diagnose(profile=profile)
    if json_output:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Shards-Kernel {report['version']} — {report['profile']} preflight")
        for check in report["checks"]:
            print(f"[{check['status']}] {check['id']}: {check['detail']}")
        print(f"Assessment: {report['assessment']}")
        print(report["scope"])
    return 0 if report["ready"] else 2
