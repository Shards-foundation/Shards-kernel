"""Read-only hygiene audit of Git-tracked repository files.

Python 3.9+, standard library and Git; Linux, macOS and Windows.
Does not modify tracked files, stages, worktrees, or Git configuration.
Advisory findings do not fail by default; --strict treats them as failures.

Examples:
    python scripts/maintenance/repo_hygiene.py --repo .
    python scripts/maintenance/repo_hygiene.py --repo . --strict
    python scripts/maintenance/repo_hygiene.py --dry-run --log-level DEBUG
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import re
import signal
import stat
import subprocess  # nosec B404 - required for fixed-argv git ls-files only
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("shards.maintenance.hygiene")
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
MAX_GIT_OUTPUT = 8 * 1024 * 1024
GIT_TIMEOUT = 30
TEXT_SUFFIXES = frozenset({
    ".py", ".md", ".txt", ".toml", ".yaml", ".yml", ".json", ".ini",
    ".cfg", ".sh", ".ps1", ".xml", ".svg", ".css", ".js", ".ts",
})
SPECIAL_NAMES = frozenset({"Makefile", "Dockerfile", "LICENSE", ".gitignore", ".editorconfig"})


class AuditError(Exception):
    """A bounded failure with no file contents or secrets."""


class JsonFormatter(logging.Formatter):
    """Produce structured JSON logs."""

    def format(self, record: logging.LogRecord) -> str:
        value: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        value.update(getattr(record, "data", {}))
        return json.dumps(value, sort_keys=True, separators=(",", ":"))


def setup_logging(level: str) -> None:
    """Initialise deterministic structured logging."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def tracked_paths(root: Path) -> List[Path]:
    """Enumerate tracked paths without interpreting repository text as shell code."""
    try:
        # Git binary and arguments are fixed; no repository text is executed.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        result = subprocess.run(  # nosec B603
            ["git", "ls-files", "--cached", "-z"],
            cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=GIT_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError("git_unavailable_or_timed_out") from exc
    if result.returncode != 0:
        raise AuditError("git_ls_files_failed")
    if len(result.stdout) > MAX_GIT_OUTPUT:
        raise AuditError("git_file_list_too_large")
    names = [os.fsdecode(item) for item in result.stdout.split(b"\x00") if item]
    return [Path(name) for name in names]


def _metadata_finding(root: Path, relative: Path, max_bytes: int) -> Optional[Tuple[str, str]]:
    """Reject unsafe or missing tracked files before reading their contents."""
    for ancestor in relative.parents:
        if ancestor == Path("."):
            break
        if (root / ancestor).is_symlink():
            return ("critical", "symlinked_tracked_directory")
    try:
        metadata = (root / relative).lstat()
    except OSError:
        return ("critical", "tracked_file_missing")
    if stat.S_ISLNK(metadata.st_mode):
        return ("advisory", "tracked_symlink_requires_review")
    if not stat.S_ISREG(metadata.st_mode):
        return ("critical", "tracked_path_not_regular_file")
    if metadata.st_size > max_bytes:
        return ("advisory", "file_above_scan_limit")
    return None


def _bounded_text(path: Path, max_bytes: int) -> Tuple[Optional[str], bytes, Optional[str]]:
    """Return a size-limited UTF-8 file read, or a safe rejection code."""
    try:
        with path.open("rb") as stream:
            content = stream.read(max_bytes + 1)
    except OSError:
        return None, b"", "tracked_file_unreadable"
    if len(content) > max_bytes:
        return None, b"", "file_above_scan_limit"
    if b"\x00" in content:
        return None, b"", "nul_byte_in_text"
    try:
        return content.decode("utf-8"), content, None
    except UnicodeDecodeError:
        return None, b"", "text_not_utf8"


def _text_findings(decoded: str, content: bytes, relative: Path) -> List[Tuple[str, str]]:
    """Check text-level hygiene independently of filesystem validation."""
    findings: List[Tuple[str, str]] = []
    if content and not content.endswith(b"\n"):
        findings.append(("advisory", "no_terminal_newline"))
    if b"\r\n" in content:
        findings.append(("advisory", "crlf_line_endings"))
    lines = decoded.splitlines()
    if any(line.endswith((" ", "\t")) for line in lines):
        findings.append(("advisory", "trailing_whitespace"))
    if any(re.match(r"^<{7} ", line) for line in lines) and any(
        re.match(r"^>{7} ", line) for line in lines
    ):
        findings.append(("critical", "merge_conflict_markers"))
    if relative.suffix == ".py":
        try:
            ast.parse(decoded, filename=str(relative))
        except (SyntaxError, ValueError, TypeError):
            findings.append(("critical", "python_syntax_invalid"))
    return findings


def file_findings(root: Path, relative: Path, max_bytes: int) -> List[Tuple[str, str]]:
    """Audit one tracked file; no write, symlink traversal or unbounded read."""
    metadata_problem = _metadata_finding(root, relative, max_bytes)
    if metadata_problem is not None:
        return [metadata_problem]
    if relative.suffix.lower() not in TEXT_SUFFIXES and relative.name not in SPECIAL_NAMES:
        return []
    decoded, content, error = _bounded_text(root / relative, max_bytes)
    if error is not None:
        severity = "advisory" if error == "file_above_scan_limit" else "critical"
        return [(severity, error)]
    if decoded is None:
        return [("critical", "text_decode_failed")]
    return _text_findings(decoded, content, relative)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse and validate command-line configuration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--max-file-mib", type=int, default=2)
    parser.add_argument("--strict", action="store_true", help="Fail on advisory findings too")
    parser.add_argument("--dry-run", action="store_true", help="Validate flags without inspecting files")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser.parse_args(argv)


def audit(root: Path, max_bytes: int, strict: bool, interrupted: List[int]) -> int:
    """Audit tracked content and report summary with explicit failure status."""
    started = time.monotonic()
    checked = 0
    critical = 0
    advisory = 0
    try:
        paths = tracked_paths(root)
        if not paths:
            raise AuditError("repository_has_no_tracked_files")
        for relative in paths:
            if interrupted:
                return 130 if interrupted[0] == signal.SIGINT else 143
            if relative.is_absolute() or ".." in relative.parts:
                raise AuditError("unsafe_git_path")
            checked += 1
            for severity, reason in file_findings(root, relative, max_bytes):
                if severity == "critical":
                    critical += 1
                else:
                    advisory += 1
                LOG.warning("finding", extra={"data": {
                    "severity": severity, "reason": reason, "path": relative.as_posix(),
                }})
        LOG.info("summary", extra={"data": {
            "files_checked": checked, "critical": critical, "advisory": advisory,
            "duration_seconds": round(time.monotonic() - started, 3),
            "scope": "tracked_worktree_only",
        }})
        return 1 if critical or (strict and advisory) else 0
    except AuditError as exc:
        LOG.error("audit_error", extra={"data": {"reason": str(exc)}})
        return 2


def main(argv: Optional[List[str]] = None) -> int:
    """Return 0 for pass, 1 for findings, 2 for errors, 130/143 for signal."""
    args = parse_args(argv)
    setup_logging(args.log_level)
    if not 1 <= args.max_file_mib <= 100:
        LOG.error("invalid_argument", extra={"data": {"reason": "max_file_mib_out_of_range"}})
        return 2
    root = args.repo.resolve()
    if not root.is_dir():
        LOG.error("invalid_argument", extra={"data": {"reason": "repository_directory_missing"}})
        return 2
    if args.dry_run:
        LOG.info("dry_run", extra={"data": {
            "root": str(root), "strict": args.strict, "max_file_mib": args.max_file_mib,
            "filesystem_mutations": 0,
        }})
        return 0
    interrupted: List[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        interrupted.append(signum)

    previous_sigint = signal.signal(signal.SIGINT, handle_signal)
    previous_sigterm = signal.signal(signal.SIGTERM, handle_signal)
    try:
        return audit(root, args.max_file_mib * 1024 * 1024, args.strict, interrupted)
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    sys.exit(main())
