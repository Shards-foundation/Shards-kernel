"""CLI entrypoint for Shards-Kernel."""

import argparse
import os
import sys
from shards_kernel._version import __version__


def main() -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="shards-kernel",
        description="Shards-Kernel: Deterministic Control Planes for AI Systems",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"shards-kernel {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    dashboard_parser = subparsers.add_parser(
        "dashboard", help="Open the optional Shards mission-control interface"
    )
    dashboard_parser.add_argument(
        "--plain", action="store_true", help="Disable colour and panels"
    )
    dashboard_parser.add_argument(
        "--no-animate", action="store_true", help="Disable startup animation"
    )
    dashboard_parser.add_argument(
        "--no-interactive", action="store_true", help="Display without input prompt"
    )

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

    # A safe preflight, NOT a production readiness certificate.
    doctor_parser = subparsers.add_parser(
        "doctor", help="Check installed SDK prerequisites (or optional service deployment)"
    )
    doctor_parser.add_argument(
        "--profile", choices=["service", "library"], default="library",
        help="library (default) checks local SDK; service checks configured operator deployment",
    )
    doctor_parser.add_argument("--json", action="store_true", help="Machine-readable report")

    demo_parser = subparsers.add_parser(
        "demo", help="Run an offline, permit-governed execution and audit-replay demonstration"
    )
    demo_parser.add_argument("--json", action="store_true", help="Machine-readable results")

    serve_parser = subparsers.add_parser(
        "serve", help="Run the restricted local operator HTTP service (not production)"
    )
    serve_parser.add_argument(
        "--config", required=True,
        help="Absolute or relative path to strict public-key-only service JSON configuration",
    )
    serve_parser.add_argument(
        "--allow-unsigned-local", action="store_true",
        help="Explicit UNSIGNED local development opt-in; never use for deployed services",
    )

    relay_parser = subparsers.add_parser(
        "mcp-relay", help="Official MCP v2 stdio relay to local authenticated operator"
    )
    relay_parser.add_argument(
        "--port", required=True, type=int,
        help="Loopback operator port (no remote URL or administrator token)",
    )

    agent_parser = subparsers.add_parser(
        "mcp-call", help="Call one signed-permit local MCP tool as an enrolled agent"
    )
    agent_parser.add_argument("--port", type=int, required=True)
    agent_parser.add_argument("--tool", choices=["echo", "add"], required=True)
    agent_parser.add_argument("--arguments-json", required=True)
    agent_parser.add_argument("--permit-file", required=True)

    mtls_parser = subparsers.add_parser(
        "mtls-ingress", help="Run pinned-client-cert HTTPS ingress to local operator (pre-production)"
    )
    mtls_parser.add_argument(
        "--config", required=True, help="Ed25519-signed mTLS ingress policy JSON"
    )
    mtls_parser.add_argument(
        "--allow-remote-listen", action="store_true",
        help="Explicit opt-in to a non-loopback TLS listener (requires signed policy)",
    )

    issuer_parser = subparsers.add_parser(
        "issuer", help="OFFLINE operator-only signing; private key via pre-opened FD"
    )
    issuer_actions = issuer_parser.add_subparsers(dest="issuer_command", required=True)
    approve = issuer_actions.add_parser("approve", help="Sign a reviewed exact permit draft")
    approve.add_argument("--draft", required=True)
    approve.add_argument("--out", required=True)
    approve.add_argument("--reviewer", required=True)
    approve.add_argument("--key-fd", required=True, type=int)
    sign = issuer_actions.add_parser("sign", help="Issue only with a distinct approved signature")
    sign.add_argument("--draft", required=True)
    sign.add_argument("--approval", required=True)
    sign.add_argument("--out", required=True)
    sign.add_argument("--approver-public-key-hex", required=True)
    sign.add_argument("--expected-issuer", required=True)
    sign.add_argument("--expected-key-id", required=True)
    sign.add_argument("--key-fd", required=True, type=int)

    args = parser.parse_args()

    if args.command is None:
        # Preserve plain help for scripts, piped output, and existing CLI tests.
        if sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("CI"):
            return _cmd_dashboard(parser)
        parser.print_help()
        return 0

    if args.command == "dashboard":
        return _cmd_dashboard(
            parser,
            plain=args.plain,
            no_animate=args.no_animate,
            interactive=False if args.no_interactive else None,
        )
    if args.command == "info":
        return _cmd_info(args.variant)
    elif args.command == "validate":
        return _cmd_validate(args.request_file)
    elif args.command == "replay":
        return _cmd_replay(args.ledger_file)
    elif args.command == "doctor":
        from shards_kernel.cli.doctor import run_doctor

        return run_doctor(profile=args.profile, json_output=args.json)
    elif args.command == "demo":
        from shards_kernel.cli.demo import run_demo

        return run_demo(json_output=args.json)
    elif args.command == "serve":
        from shards_kernel.cli.service import run_service

        return run_service(args.config, allow_unsigned_local=args.allow_unsigned_local)
    elif args.command == "issuer":
        from shards_kernel.cli.issuer_command import run_issuer_command

        return run_issuer_command(args)
    elif args.command == "mcp-relay":
        from shards_kernel.integrations.mcp_local_relay import run_local_mcp_agent_relay

        return run_local_mcp_agent_relay(args.port)
    elif args.command == "mcp-call":
        from shards_kernel.cli.mcp_call import main as call_agent
        return call_agent([
            "--port", str(args.port), "--tool", args.tool,
            "--arguments-json", args.arguments_json,
            "--permit-file", args.permit_file,
        ])
    elif args.command == "mtls-ingress":
        from shards_kernel.integrations.mtls_ingress import run_mtls_ingress

        return run_mtls_ingress(
            args.config, allow_remote_listen=args.allow_remote_listen
        )

    return 0


def _cmd_dashboard(parser: argparse.ArgumentParser, *, plain: bool = False,
                   no_animate: bool = False, interactive=None) -> int:
    """Presentation-only selection of existing safe CLI commands."""
    from shards_kernel.cli.mission_control import run_dashboard

    selection = run_dashboard(
        plain=plain, no_animate=no_animate, interactive=interactive
    )
    if selection == "info":
        return _cmd_info("strict")
    if selection == "doctor":
        from shards_kernel.cli.doctor import run_doctor

        # This is operational preflight, not merely a local library install
        # check. Keep fallback and Textual status semantics consistent.
        return run_doctor(profile="service", json_output=False)
    if selection == "demo":
        from shards_kernel.cli.demo import run_demo

        return run_demo(json_output=False)
    if selection == "help":
        parser.print_help()
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
