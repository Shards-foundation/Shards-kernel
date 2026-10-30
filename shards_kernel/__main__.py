"""CLI entrypoint for Kernels."""

import argparse
import sys
from shards_kernel._version import __version__


def main() -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="shards-kernel",
        description="Kernels: Deterministic Control Planes for AI Systems",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"shards-kernel {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Info command
    info_parser = subparsers.add_parser("info", help="Display kernel information")
    info_parser.add_argument(
        "--variant",
        choices=["strict", "permissive", "evidence-first", "dual-channel"],
        default="strict",
        help="Kernel variant to display info for",
    )

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate", help="Validate a request JSON file"
    )
    validate_parser.add_argument(
        "request_file",
        help="Path to JSON file containing request",
    )

    # Replay command
    replay_parser = subparsers.add_parser(
        "replay", help="Replay and verify an audit ledger"
    )
    replay_parser.add_argument(
        "ledger_file",
        help="Path to JSON file containing audit ledger",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "info":
        return _cmd_info(args.variant)
    elif args.command == "validate":
        return _cmd_validate(args.request_file)
    elif args.command == "replay":
        return _cmd_replay(args.ledger_file)

    return 0


def _cmd_info(variant: str) -> int:
    """Display information about a kernel variant."""
    variants_info = {
        "strict": {
            "name": "Strict Kernel",
            "fail_closed": True,
            "require_jurisdiction": True,
            "require_audit": True,
            "description": "Maximum enforcement. Requires tool_call for execution.",
        },
        "permissive": {
            "name": "Permissive Kernel",
            "fail_closed": True,
            "require_jurisdiction": True,
            "require_audit": True,
            "description": "Relaxed ambiguity thresholds. Accepts intent-only requests.",
        },
        "evidence-first": {
            "name": "Evidence-First Kernel",
            "fail_closed": True,
            "require_jurisdiction": True,
            "require_audit": True,
            "description": "Requires evidence field for ALLOW decisions.",
        },
        "dual-channel": {
            "name": "Dual-Channel Kernel",
            "fail_closed": True,
            "require_jurisdiction": True,
            "require_audit": True,
            "description": "Requires constraints dict with scope, non_goals, success_criteria.",
        },
    }

    info = variants_info[variant]
    print(f"Variant: {info['name']}")
    print(f"Fail-Closed: {info['fail_closed']}")
    print(f"Require Jurisdiction: {info['require_jurisdiction']}")
    print(f"Require Audit: {info['require_audit']}")
    print(f"Description: {info['description']}")
    return 0


def _cmd_validate(request_file: str) -> int:
    """Validate a request JSON file."""
    import json
    from shards_kernel.common.types import KernelRequest
    from shards_kernel.common.validate import validate_request

    try:
        with open(request_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {request_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1

    try:
        request = KernelRequest(
            request_id=data.get("request_id", ""),
            ts_ms=data.get("ts_ms", 0),
            actor=data.get("actor", ""),
            intent=data.get("intent", ""),
            tool_call=data.get("tool_call"),
            params=data.get("params", {}),
            evidence=data.get("evidence"),
        )
        errors = validate_request(request)
        if errors:
            print("Validation failed:")
            for error in errors:
                print(f"  - {error}")
            return 1
        print("Validation passed.")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _cmd_replay(ledger_file: str) -> int:
    """Replay and verify an audit ledger."""
    import json
    from shards_kernel.audit.replay import replay_and_verify

    try:
        with open(ledger_file, "r") as f:
            entries = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {ledger_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1

    try:
        is_valid, errors = replay_and_verify(entries)
        if is_valid:
            print(f"Ledger valid. {len(entries)} entries verified.")
            return 0
        else:
            print("Ledger verification failed:")
            for error in errors:
                print(f"  - {error}")
            return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
