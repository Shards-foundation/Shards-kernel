"""Read-only GitHub Actions failure and stale-run monitor.

Python 3.9+, standard library only. Supports public repositories without a
token, or private repositories when GITHUB_TOKEN is injected securely.
Only contacts the GitHub REST API; does not rerun, cancel, delete or approve.

Examples:
    python scripts/maintenance/github_actions_watch.py --dry-run
    python scripts/maintenance/github_actions_watch.py --repo Shards-foundation/Shards-kernel
    python scripts/maintenance/github_actions_watch.py --repo Shards-foundation/Shards-kernel --branch main --lookback-hours 168

Exit 0: observed runs healthy; 1: critical failed or stale runs;
2: incomplete evidence, invalid arguments, or transport/API failure;
130/143: interrupted by SIGINT/SIGTERM. A passing observation is NOT proof
of protected branch settings or production release acceptance.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("shards.maintenance.actions")
API_ORIGIN = "https://api.github.com"
USER_AGENT = "shards-repo-maintenance/1.0"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
PER_PAGE = 100
MAX_ATTEMPTS = 5
MAX_PAGES = 20
RETRIABLE_HTTP = frozenset({408, 429, 500, 502, 503, 504})
CRITICAL_CONCLUSIONS = frozenset({"failure", "timed_out", "action_required", "startup_failure"})
NONCRITICAL_CONCLUSIONS = frozenset({"cancelled", "skipped", "neutral"})
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class MonitorError(Exception):
    """A redacted, actionable monitoring error."""

    def __init__(self, code: str, retriable: bool = False) -> None:
        super().__init__(code)
        self.retriable = retriable


@dataclass(frozen=True)
class Options:
    """Validated GitHub Actions monitoring configuration."""

    repo: str
    branch: str
    lookback_hours: int
    stale_minutes: int
    max_pages: int
    timeout: float
    attempts: int
    dry_run: bool


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following redirect destinations."""

    def redirect_request(
        self, request: urllib.request.Request, fp: Any, code: int,
        msg: str, headers: Any, newurl: str,
    ) -> None:
        return None


class JsonFormatter(logging.Formatter):
    """Emit JSON logging records for schedulers and collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "data", {}))
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def setup_logging(level: str) -> None:
    """Configure JSON logging without disclosing credentials."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="Shards-foundation/Shards-kernel")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--stale-minutes", type=int, default=180)
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true", help="No network access")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser.parse_args(argv)


def validate(args: argparse.Namespace) -> Options:
    """Validate destination and operational bounds before network access."""
    import math

    parts = args.repo.split("/")
    if len(parts) != 2 or not all(SAFE_NAME.fullmatch(value) and value not in {".", ".."} for value in parts):
        raise MonitorError("invalid_repository")
    if not args.branch or len(args.branch) > 200 or not re.fullmatch(r"[A-Za-z0-9_./-]+", args.branch) or ".." in args.branch:
        raise MonitorError("invalid_branch")
    if not 1 <= args.lookback_hours <= 24 * 90:
        raise MonitorError("invalid_lookback_hours")
    if not 1 <= args.stale_minutes <= 24 * 60 * 30:
        raise MonitorError("invalid_stale_minutes")
    if not 1 <= args.max_pages <= MAX_PAGES:
        raise MonitorError("invalid_max_pages")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120:
        raise MonitorError("invalid_timeout")
    if not 1 <= args.attempts <= MAX_ATTEMPTS:
        raise MonitorError("invalid_attempts")
    return Options(
        args.repo, args.branch, args.lookback_hours, args.stale_minutes,
        args.max_pages, args.timeout, args.attempts, args.dry_run,
    )


def parse_timestamp(value: Any) -> datetime:
    """Decode a UTC-aware ISO 8601 timestamp, refusing missing evidence."""
    if not isinstance(value, str):
        raise MonitorError("run_timestamp_missing")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitorError("run_timestamp_invalid") from exc
    if dt.tzinfo is None:
        raise MonitorError("run_timestamp_has_no_timezone")
    return dt.astimezone(timezone.utc)


def fetch_page(
    options: Options, page: int, token: Optional[str], interrupted: List[int],
) -> Dict[str, Any]:
    """Read one paginated Actions result with bounded retry and timeout."""
    params = urllib.parse.urlencode({
        "branch": options.branch, "per_page": PER_PAGE, "page": page,
    })
    owner, repo = options.repo.split("/")
    url = f"{API_ORIGIN}/repos/{owner}/{repo}/actions/runs?{params}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    attempt = 0
    while True:
        attempt += 1
        if interrupted:
            raise MonitorError("interrupted")
        try:
            with opener.open(request, timeout=options.timeout) as response:
                if response.status != 200:
                    raise MonitorError("github_unexpected_http_status")
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise MonitorError("github_response_too_large")
            payload = json.loads(content.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
                raise MonitorError("github_response_shape_invalid")
            return payload
        except urllib.error.HTTPError as exc:
            problem = MonitorError(f"github_http_{exc.code}", exc.code in RETRIABLE_HTTP)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            problem = MonitorError("github_network_failure", True)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MonitorError("github_invalid_json") from None
        if not problem.retriable or attempt == options.attempts:
            raise problem
        backoff = min(8.0, float(2 ** (attempt - 1)))
        LOG.warning("github_retry", extra={"data": {"attempt": attempt, "reason": str(problem)}})
        # Do not retry indefinitely if a signal has been received.
        deadline = time.monotonic() + backoff
        while time.monotonic() < deadline:
            if interrupted:
                raise MonitorError("interrupted")
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


def collect_runs(
    options: Options, token: Optional[str], now: datetime, interrupted: List[int],
) -> Tuple[List[Dict[str, Any]], bool, int]:
    """Collect bounded recent branch runs; report evidence truncation."""
    threshold = now - timedelta(hours=options.lookback_hours)
    runs: List[Dict[str, Any]] = []
    pages = 0
    complete = False
    for page in range(1, options.max_pages + 1):
        payload = fetch_page(options, page, token, interrupted)
        pages += 1
        batch = payload["workflow_runs"]
        if not batch:
            complete = True
            break
        page_is_old = False
        for item in batch:
            if not isinstance(item, dict):
                raise MonitorError("github_run_shape_invalid")
            created = parse_timestamp(item.get("created_at"))
            if created <= threshold:
                page_is_old = True
                continue
            runs.append(item)
        if len(batch) < PER_PAGE or page_is_old:
            complete = True
            break
        LOG.info("page_checked", extra={"data": {"page": page, "recent_runs": len(runs)}})
    return runs, complete, pages


def classify(run: Dict[str, Any], now: datetime, stale_minutes: int) -> str:
    """Classify an action run without mistaking pending for success."""
    created = parse_timestamp(run.get("created_at"))
    if created > now + timedelta(minutes=5):
        return "invalid_clock"
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status == "completed":
        if conclusion == "success":
            return "success"
        if conclusion in CRITICAL_CONCLUSIONS:
            return "failed"
        if conclusion in NONCRITICAL_CONCLUSIONS:
            return "advisory"
        return "unknown_conclusion"
    if status in {"queued", "in_progress", "waiting", "requested", "pending"}:
        return "stale" if now - created > timedelta(minutes=stale_minutes) else "pending"
    return "unknown_status"


def monitor(
    options: Options, token: Optional[str], interrupted: List[int],
    now: Optional[datetime] = None,
) -> int:
    """Read GitHub Actions state and emit an auditable summary."""
    started = time.monotonic()
    now = datetime.now(timezone.utc) if now is None else now
    try:
        runs, complete, pages = collect_runs(options, token, now, interrupted)
        results = {"success": 0, "failed": 0, "stale": 0, "pending": 0,
                   "advisory": 0, "unknown_status": 0, "unknown_conclusion": 0,
                   "invalid_clock": 0}
        for item in runs:
            category = classify(item, now, options.stale_minutes)
            results[category] += 1
            if category not in {"success", "pending"}:
                LOG.warning("workflow_run_anomaly", extra={"data": {
                    "category": category, "run_id": item.get("id"),
                    "workflow": str(item.get("name", ""))[:160],
                }})
        LOG.info("summary", extra={"data": {
            **results, "runs_checked": len(runs), "pages": pages,
            "complete": complete, "branch": options.branch, "repo": options.repo,
            "duration_seconds": round(time.monotonic() - started, 3),
            "scope": "github_actions_observation_only",
        }})
        if not complete or not runs:
            LOG.error("insufficient_evidence", extra={"data": {
                "reason": "pagination_incomplete" if not complete else "no_recent_workflow_runs",
            }})
            return 2
        if any(results[key] for key in (
            "failed", "stale", "unknown_status", "unknown_conclusion", "invalid_clock",
        )):
            return 1
        return 0
    except MonitorError as exc:
        LOG.error("monitor_error", extra={"data": {"reason": str(exc)}})
        return 2


def main(argv: Optional[List[str]] = None) -> int:
    """Program entrypoint, honouring signals and exit codes."""
    args = parse_args(argv)
    setup_logging(args.log_level)
    try:
        options = validate(args)
    except MonitorError as exc:
        LOG.error("configuration_rejected", extra={"data": {"reason": str(exc)}})
        return 2
    if options.dry_run:
        LOG.info("dry_run", extra={"data": {
            "repo": options.repo, "branch": options.branch,
            "lookback_hours": options.lookback_hours, "network_requests": 0,
        }})
        return 0
    interrupted: List[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        interrupted.append(signum)

    previous_sigint = signal.signal(signal.SIGINT, handle_signal)
    previous_sigterm = signal.signal(signal.SIGTERM, handle_signal)
    try:
        status = monitor(options, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), interrupted)
        if interrupted:
            return 130 if interrupted[0] == signal.SIGINT else 143
        return status
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    sys.exit(main())
