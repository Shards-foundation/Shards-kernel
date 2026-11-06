"""Read-only security audit of GitHub Actions workflow source.

Python 3.9+, standard library only. This is a targeted static check, NOT
a complete YAML or GitHub Actions security parser. Avoids loading untrusted
workflows, running commands, or changing repository files.

Examples:
    python scripts/maintenance/workflow_safety.py --repo .
    python scripts/maintenance/workflow_safety.py --repo . --strict
    python scripts/maintenance/workflow_safety.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("shards.maintenance.workflows")
MAX_WORKFLOW_BYTES = 512 * 1024
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^#\s]+)", re.MULTILINE)
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.\-/]+@[a-f0-9]{40}$")
URL_SHELL_PIPE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b")
PERMISSIONS_WRITE_ALL = re.compile(r"^\s*permissions:\s*write-all(?:\s*#.*)?$", re.MULTILINE)
PERSIST_CREDENTIALS = re.compile(r"^\s*persist-credentials:\s*true(?:\s*#.*)?$", re.MULTILINE)
CHECKOUT_UNTRUSTED = re.compile(r"^\s*ref:\s*.*(?:github\.event\.pull_request\.(?:head|merge)|github\.head_ref)", re.MULTILINE)


class JsonFormatter(logging.Formatter):
    """Format deterministic machine-readable events."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "data", {}))
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def setup_logging(level: str) -> None:
    """Configure one JSON logger."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def analyse_workflow(source: str) -> List[Tuple[str, str]]:
    """Return targeted, explainable warnings from workflow text.

    Conservative patterns intentionally avoid pretending this is a full
    workflow or expression interpreter.
    """
    findings: List[Tuple[str, str]] = []
    for match in USES.finditer(source):
        ref = match.group(1)
        if ref.startswith("./"):
            continue
        if ref.startswith("docker://"):
            if not re.search(r"@sha256:[a-f0-9]{64}$", ref):
                findings.append(("advisory", "docker_image_not_digest_pinned"))
        elif not PINNED_ACTION.fullmatch(ref):
            findings.append(("advisory", "action_not_full_sha_pinned"))
    if PERMISSIONS_WRITE_ALL.search(source):
        findings.append(("critical", "workflow_token_write_all"))
    if PERSIST_CREDENTIALS.search(source):
        findings.append(("advisory", "checkout_credentials_persisted"))
    if URL_SHELL_PIPE.search(source):
        findings.append(("critical", "remote_script_piped_to_shell"))
    if re.search(r"^\s*pull_request_target:\s*(?:$|[#\[{])", source, re.MULTILINE):
        findings.append(("advisory", "pull_request_target_requires_trust_review"))
        if CHECKOUT_UNTRUSTED.search(source):
            findings.append(("critical", "privileged_event_checkout_of_pr_head"))
    return findings


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--strict", action="store_true", help="Treat advisory findings as failures")
    parser.add_argument("--dry-run", action="store_true", help="Validate input without file reads")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser.parse_args(argv)


def audit_workflows(root: Path, strict: bool, interrupted: List[int]) -> int:
    """Inspect a bounded directory of YAML files without evaluating workflow code."""
    started = time.monotonic()
    folder = root / ".github" / "workflows"
    if not folder.is_dir() or folder.is_symlink():
        LOG.error("audit_error", extra={"data": {"reason": "workflow_directory_not_found"}})
        return 2
    critical = 0
    advisory = 0
    checked = 0
    paths = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
    if not paths:
        LOG.error("audit_error", extra={"data": {"reason": "no_workflows_found"}})
        return 2
    for path in paths:
        if interrupted:
            return 130 if interrupted[0] == signal.SIGINT else 143
        checked += 1
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_WORKFLOW_BYTES:
                raise ValueError("unsafe_workflow_file")
            content = path.read_bytes()
            if len(content) > MAX_WORKFLOW_BYTES or b"\x00" in content:
                raise ValueError("unsafe_workflow_size_or_encoding")
            source = content.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            LOG.error("audit_error", extra={"data": {
                "path": path.relative_to(root).as_posix(), "reason": "workflow_file_unreadable",
            }})
            return 2
        for severity, reason in analyse_workflow(source):
            if severity == "critical":
                critical += 1
            else:
                advisory += 1
            LOG.warning("workflow_finding", extra={"data": {
                "severity": severity, "reason": reason, "path": path.relative_to(root).as_posix(),
            }})
    LOG.info("summary", extra={"data": {
        "workflows_checked": checked, "critical": critical, "advisory": advisory,
        "strict": strict, "duration_seconds": round(time.monotonic() - started, 3),
        "scope": "targeted_static_checks_not_yaml_interpreter",
    }})
    return 1 if critical or (strict and advisory) else 0


def main(argv: Optional[List[str]] = None) -> int:
    """Entrypoint; exit 0 pass, 1 findings, 2 operational failure."""
    args = parse_args(argv)
    setup_logging(args.log_level)
    root = args.repo.resolve()
    if not root.is_dir():
        LOG.error("invalid_argument", extra={"data": {"reason": "repository_missing"}})
        return 2
    if args.dry_run:
        LOG.info("dry_run", extra={"data": {"repo": str(root), "files_modified": 0}})
        return 0
    interrupted: List[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        interrupted.append(signum)

    old_int = signal.signal(signal.SIGINT, handle_signal)
    old_term = signal.signal(signal.SIGTERM, handle_signal)
    try:
        return audit_workflows(root, args.strict, interrupted)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
