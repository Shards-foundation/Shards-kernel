#!/usr/bin/env python3
"""Example 02: export and independently verify a kernel evidence bundle."""

from shards_kernel.audit.replay import replay_and_verify
from shards_kernel.common.codec import audit_entry_to_dict
from shards_kernel.common.types import KernelConfig, KernelRequest, VirtualClock
from shards_kernel.variants.strict_kernel import StrictKernel


def main() -> None:
    """Run one request, export the ledger, and verify its hash chain."""
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(
            kernel_id="demo-evidence-002",
            variant="strict",
            clock=VirtualClock(2_000),
        )
    )
    receipt = kernel.submit(
        KernelRequest(
            request_id="demo-request-002",
            ts_ms=2_000,
            actor="demo-operator",
            intent="Demonstrate independently verifiable evidence",
        )
    )
    evidence = kernel.export_evidence()
    entries = [audit_entry_to_dict(entry) for entry in evidence.ledger_entries]
    valid, errors = replay_and_verify(entries, expected_root_hash=evidence.root_hash)

    print(f"Request decision: {receipt.decision.value}")
    print(f"Evidence entries: {len(entries)}")
    print(f"Root hash: {evidence.root_hash}")
    print(f"Hash-chain verification: {'PASS' if valid else 'FAIL'}")
    if errors:
        for error in errors:
            print(f"  - {error}")
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
