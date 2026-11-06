"""Read-only expiry and signature preflight for a signed operator policy.

Python 3.9+. Requires Shards-Kernel's existing crypto optional extra.
The validator imports the kernel's authoritative policy verifier and DOES
NOT create a policy, issue permits, open an audit DB or start the service.
This cannot prove anti-rollback or distributed production readiness.

Examples:
    python scripts/ops/policy_preflight.py --policy /srv/shards/policy.json
    python scripts/ops/policy_preflight.py --policy ./policy.json --min-ttl-seconds 86400
    python scripts/ops/policy_preflight.py --policy ./policy.json --expected-kernel-id local-operator

Set SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX to the independently pinned 64-character
lowercase Ed25519 public key (never to private signing material).
Install: python -m pip install -e '.[crypto]'
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

LOG = logging.getLogger("shards.ops.policy")
MAX_MIN_TTL = 30 * 24 * 60 * 60


class JSONFormatter(logging.Formatter):
    """Emit bounded, machine-readable result events."""

    def format(self, record: logging.LogRecord) -> str:
        result = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        result.update(getattr(record, "data", {}))
        return json.dumps(result, separators=(",", ":"), sort_keys=True)


def configure_logging(level: str) -> None:
    """Configure one structured logger."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse CLI options for offline signed policy checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--min-ttl-seconds", type=int, default=3600,
                        help="Minimum remaining signed-policy lifetime; default 1 hour")
    parser.add_argument("--minimum-revision", type=int, default=1)
    parser.add_argument("--expected-kernel-id", default=None)
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"),
                        default="INFO")
    return parser.parse_args(argv)


def preflight(
    policy: Path,
    *,
    trusted_key: str,
    min_ttl_seconds: int,
    minimum_revision: int,
    expected_kernel_id: Optional[str],
    now_ms: Optional[int] = None,
) -> dict[str, Any]:
    """Verify a signed policy with the kernel's own Ed25519 implementation.

    Args:
        policy: Path to an existing signed policy JSON file.
        trusted_key: Independently pinned Ed25519 public key hex.
        min_ttl_seconds: Minimum permitted remaining validity window.
        minimum_revision: Operator-provided revision floor, not a durable anchor.
        expected_kernel_id: Optional exact expected service audience.
        now_ms: UTC milliseconds. Intended only for deterministic testing.

    Returns:
        Credential-free summary on successful verification.

    Raises:
        ValueError: Unsafe input or failed validity threshold.
        OSError: Unable to read policy file.
        ImportError: Uninstalled runtime or cryptography extra.
    """
    if not 0 <= min_ttl_seconds <= MAX_MIN_TTL:
        raise ValueError("--min-ttl-seconds must be between 0 and 2592000")
    if minimum_revision < 1:
        raise ValueError("--minimum-revision must be at least 1")
    if expected_kernel_id is not None and (
        not expected_kernel_id or len(expected_kernel_id) > 128 or
        any(not (ch.isalnum() or ch in "_.-") for ch in expected_kernel_id)
    ):
        raise ValueError("Invalid --expected-kernel-id")
    if len(trusted_key) != 64 or any(ch not in "0123456789abcdef" for ch in trusted_key):
        raise ValueError("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX must be 64 lowercase hex characters")
    from shards_kernel.cli.signed_policy import load_signed_policy

    if now_ms is None:
        now_ms = time.time_ns() // 1_000_000
    verified = load_signed_policy(
        str(policy), trusted_public_key_hex=trusted_key, current_time_ms=now_ms,
    )
    remaining_ms = verified.expires_at_ms - now_ms
    if remaining_ms < min_ttl_seconds * 1_000:
        raise ValueError("Policy remaining lifetime is below configured minimum")
    if verified.revision < minimum_revision:
        raise ValueError("Policy revision below configured floor")
    if expected_kernel_id is not None and verified.config.kernel_id != expected_kernel_id:
        raise ValueError("Signed policy kernel identity does not match expected ID")
    return {
        "result": "SIGNED_POLICY_VALID",
        "kernel_id": verified.config.kernel_id,
        "revision": verified.revision,
        "remaining_seconds": remaining_ms // 1_000,
        "digest_sha256": verified.digest,
        "scope": "local_signature_and_expiry_only_not_deployed_readiness",
    }


def main(argv: Optional[list[str]] = None) -> int:
    """Fail closed; never log raw policy, database path or secret material."""
    args = parse_args(argv)
    configure_logging(args.log_level)
    started = time.monotonic()
    exit_signal: list[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        exit_signal.append(signum)

    previous_interrupt = signal.signal(signal.SIGINT, handle_signal)
    previous_term = None
    if hasattr(signal, "SIGTERM"):
        previous_term = signal.signal(signal.SIGTERM, handle_signal)
    result = 0
    try:
        report = preflight(
            args.policy,
            trusted_key=os.environ.get("SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX", ""),
            min_ttl_seconds=args.min_ttl_seconds,
            minimum_revision=args.minimum_revision,
            expected_kernel_id=args.expected_kernel_id,
        )
        LOG.info("policy_verified", extra={"data": report})
    except (ValueError, OSError, ImportError, TypeError, KeyError) as exc:
        result = 2
        # Errors from imported parsers can echo policy text/paths. Redact them.
        reason = "DEPENDENCY_MISSING_INSTALL_SHARDS_KERNEL_CRYPTO" if isinstance(exc, ImportError) else "POLICY_REJECTED"
        LOG.error("policy_rejected", extra={"data": {"reason": reason}})
    LOG.info("summary", extra={"data": {
        "checked": 1, "failed": int(result != 0),
        "duration_seconds": round(time.monotonic() - started, 3),
        "scope": "read_only_preflight_not_production_certificate",
    }})
    signal.signal(signal.SIGINT, previous_interrupt)
    if previous_term is not None:
        signal.signal(signal.SIGTERM, previous_term)
    return (130 if exit_signal[0] == signal.SIGINT else 143) if exit_signal else result


if __name__ == "__main__":
    sys.exit(main())
