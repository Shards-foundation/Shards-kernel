"""Mandatory local end-to-end release gate.

This is deliberately narrower than production certification: the suite proves
real local OS processes, MCP stdio, loopback HTTP, TLS sockets and persisted
replay. It does not claim remote MCP, multi-host durability or live trading.
"""

from __future__ import annotations

import sys

import pytest

# Exact node IDs make additions and removals a reviewed release decision.
# No module-level importorskip or POSIX skip may silently turn the gate green.
SCENARIOS = (
    "tests/test_separate_issuer_process_e2e.py::test_separate_approver_issuer_and_kernel_processes",
    "tests/test_mcp_agent_relay.py::test_two_real_mcp_stdio_clients_separate_signed_agent_identity_across_restart",
    "tests/test_mcp_agent_relay.py::test_two_mcp_clients_execute_concurrently_with_isolated_authority",
    "tests/test_mtls_agent_ingress.py::test_real_mutual_tls_agent_cert_and_bearer_and_permit_separation",
)


class StrictE2EGate:
    """Reject missing, skipped, xfailed, and unexpectedly deselected tests."""

    def __init__(self) -> None:
        self.collected = 0
        self.passed = 0
        self.skipped = 0

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = len(session.items)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped:
            self.skipped += 1
        if report.when == "call" and report.passed and not hasattr(report, "wasxfail"):
            self.passed += 1

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        expected = len(SCENARIOS)
        if self.collected != expected or self.passed != expected or self.skipped:
            print(
                "E2E RELEASE GATE FAILED: "
                f"expected={expected}, collected={self.collected}, "
                f"passed={self.passed}, skipped={self.skipped}",
                file=sys.stderr,
            )
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


def supported_environment(
    python_version: tuple[int, ...] | None = None,
    platform: str | None = None,
) -> bool:
    """Explicitly gate the supported OS/runtime, independently testable in CI."""
    version = sys.version_info if python_version is None else python_version
    current_platform = sys.platform if platform is None else platform
    return version >= (3, 11) and current_platform == "linux"


def main() -> int:
    if not supported_environment():
        print("E2E release gate requires Linux and Python 3.11+", file=sys.stderr)
        return 2

    gate = StrictE2EGate()
    result = pytest.main(
        [
            "-q",
            "-ra",
            "--strict-markers",
            "-o",
            "addopts=",
            "--junitxml=e2e-results.xml",
            *SCENARIOS,
        ],
        plugins=[gate],
    )
    return int(result)


if __name__ == "__main__":
    raise SystemExit(main())
