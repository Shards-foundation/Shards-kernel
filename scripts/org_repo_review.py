#!/usr/bin/env python3
"""Read-only GitHub organisation repository inventory and maintenance triage.

Requires Python 3.9+ and only the standard library. This utility never clones,
executes repository code, resets branches, deletes worktrees or writes reports.

Examples:
    python scripts/org_repo_review.py --org Shards-foundation
    python scripts/org_repo_review.py --org Shards-foundation --format markdown
    python scripts/org_repo_review.py --org Shards-foundation --check-branches --strict
    python scripts/org_repo_review.py --org Shards-foundation --dry-run

Supply GITHUB_TOKEN through the environment for private organisation metadata.
This script is not a branch-protection certification or security scanner.
To save a report, redirect stdout to a separately managed destination.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
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

API_ORIGIN = "https://api.github.com"
USER_AGENT = "shards-safe-org-inventory/1.0"
PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PAGES = 50
MAX_RETRIES = 5
DEFAULT_TIMEOUT = 8.0
DEFAULT_ATTEMPTS = 3
DEFAULT_MAX_PAGES = 10
DEFAULT_STALE_DAYS = 180
MAX_REPOS = 5000
BACKOFF_CAP_SECONDS = 8.0
HTTP_TRANSIENT = frozenset({408, 429, 500, 502, 503, 504})
ORG_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
LOG = logging.getLogger("shards.org_inventory")


class InventoryError(Exception):
    """Redacted inventory failure with a known reason code."""

    def __init__(self, reason: str, *, retryable: bool = False) -> None:
        super().__init__(reason)
        self.retryable = retryable


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not forward a bearer token through an HTTP redirect."""

    def redirect_request(
        self, request: urllib.request.Request, fp: Any, code: int,
        msg: str, headers: Any, newurl: str,
    ) -> None:
        return None


class JsonFormatter(logging.Formatter):
    """Emit structured logs without URLs, tokens or exception traces."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "data", {}))
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Settings:
    """Fully validated, non-mutating inventory configuration."""

    organisation: str
    timeout: float
    attempts: int
    max_pages: int
    repo_limit: int
    stale_days: int
    check_branches: bool
    strict: bool
    report_format: str
    dry_run: bool


def configure_logging(level: str) -> None:
    """Reserve stderr for structured operational events."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse safe, explicit CLI flags; reject legacy destructive options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--repo-limit", type=int, default=0, help="0 means all available")
    parser.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    parser.add_argument("--check-branches", action="store_true", help="Also inspect default-branch protection")
    parser.add_argument("--strict", action="store_true", help="Nonzero exit for advisory findings")
    parser.add_argument("--format", choices=("json", "markdown", "none"), default="json")
    parser.add_argument("--dry-run", action="store_true", help="No network access or filesystem writes")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser.parse_args(argv)


def validate(args: argparse.Namespace) -> Settings:
    """Validate ranges and the GitHub organisation before any HTTP request."""
    if not ORG_NAME.fullmatch(args.org) or "--" in args.org:
        raise InventoryError("invalid_organisation")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120:
        raise InventoryError("invalid_timeout")
    if not 1 <= args.attempts <= MAX_RETRIES:
        raise InventoryError("invalid_attempts")
    if not 1 <= args.max_pages <= MAX_PAGES:
        raise InventoryError("invalid_max_pages")
    if not 0 <= args.repo_limit <= MAX_REPOS:
        raise InventoryError("invalid_repo_limit")
    if not 1 <= args.stale_days <= 3650:
        raise InventoryError("invalid_stale_days")
    return Settings(args.org, args.timeout, args.attempts, args.max_pages,
                    args.repo_limit, args.stale_days, args.check_branches,
                    args.strict, args.format, args.dry_run)


def parse_datetime(value: Any) -> datetime:
    """Parse GitHub timestamps as timezone-aware UTC values."""
    if not isinstance(value, str):
        raise InventoryError("invalid_github_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryError("invalid_github_timestamp") from exc
    if parsed.tzinfo is None:
        raise InventoryError("timestamp_missing_timezone")
    return parsed.astimezone(timezone.utc)


def make_opener() -> urllib.request.OpenerDirector:
    """Use TLS directly with no proxy or cross-origin redirect support."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def read_api(
    opener: urllib.request.OpenerDirector, path: str, settings: Settings,
    token: Optional[str], stopped: List[int],
) -> Any:
    """Make a bounded GET call to a fixed GitHub API origin with retries."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT,
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        if "\r" in token or "\n" in token or len(token) > 2048:
            raise InventoryError("invalid_token_format")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API_ORIGIN + path, headers=headers, method="GET")
    attempt = 0
    while True:
        attempt += 1
        if stopped:
            raise InventoryError("interrupted")
        try:
            with opener.open(request, timeout=settings.timeout) as response:
                if response.status != 200:
                    raise InventoryError("github_unexpected_http_status")
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise InventoryError("github_response_too_large")
            return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            failure = InventoryError(f"github_http_{exc.code}", retryable=exc.code in HTTP_TRANSIENT)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            failure = InventoryError("github_transport_error", retryable=True)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InventoryError("github_invalid_json") from None
        if not failure.retryable or attempt == settings.attempts:
            raise failure
        LOG.warning("api_retry", extra={"data": {"attempt": attempt, "reason": str(failure)}})
        deadline = time.monotonic() + min(BACKOFF_CAP_SECONDS, float(2 ** (attempt - 1)))
        while time.monotonic() < deadline:
            if stopped:
                raise InventoryError("interrupted")
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


def validate_repo(raw: Any, organisation: str) -> Dict[str, Any]:
    """Allowlist inventory metadata, rejecting inconsistent repository identity."""
    if not isinstance(raw, dict):
        raise InventoryError("github_repo_not_object")
    name = raw.get("name")
    full_name = raw.get("full_name")
    if not isinstance(name, str) or not REPO_NAME.fullmatch(name):
        raise InventoryError("github_repo_name_invalid")
    if not isinstance(full_name, str) or full_name.casefold() != f"{organisation}/{name}".casefold():
        raise InventoryError("github_repo_identity_mismatch")
    if type(raw.get("archived")) is not bool or type(raw.get("disabled")) is not bool:
        raise InventoryError("github_repo_status_invalid")
    if type(raw.get("private")) is not bool or type(raw.get("fork")) is not bool:
        raise InventoryError("github_repo_visibility_invalid")
    branch = raw.get("default_branch")
    if branch is not None and (not isinstance(branch, str) or not branch or len(branch) > 200):
        raise InventoryError("github_default_branch_invalid")
    pushed = raw.get("pushed_at")
    if pushed is not None:
        parse_datetime(pushed)
    return {
        "name": name,
        "full_name": full_name,
        "archived": raw["archived"], "disabled": raw["disabled"],
        "private": raw["private"], "fork": raw["fork"],
        "default_branch": branch, "pushed_at": pushed,
        "branch_protected": "NOT_CHECKED",
        "findings": [],
    }


def collect_repos(
    opener: urllib.request.OpenerDirector, settings: Settings,
    token: Optional[str], stopped: List[int],
) -> Tuple[List[Dict[str, Any]], int, bool]:
    """Return repositories, pages and whether the observation is complete."""
    output: List[Dict[str, Any]] = []
    seen = set()
    for page in range(1, settings.max_pages + 1):
        params = urllib.parse.urlencode({"per_page": PAGE_SIZE, "page": page, "type": "all"})
        raw = read_api(opener, f"/orgs/{settings.organisation}/repos?{params}", settings, token, stopped)
        if not isinstance(raw, list):
            raise InventoryError("github_repo_page_invalid")
        if len(raw) > PAGE_SIZE:
            raise InventoryError("github_repo_page_oversized")
        for item in raw:
            if settings.repo_limit and len(output) == settings.repo_limit:
                return output, page, False
            repo = validate_repo(item, settings.organisation)
            if repo["name"].casefold() in seen:
                raise InventoryError("github_duplicate_repo")
            seen.add(repo["name"].casefold())
            output.append(repo)
            if len(output) > MAX_REPOS:
                raise InventoryError("github_repo_limit_exceeded")
        LOG.info("page_checked", extra={"data": {"page": page, "repositories": len(output)}})
        if len(raw) < PAGE_SIZE:
            return output, page, True
        if settings.repo_limit and len(output) >= settings.repo_limit:
            return output, page, False
    raise InventoryError("inventory_pagination_limit")


def add_risk_flags(repo: Dict[str, Any], now: datetime, stale_days: int) -> None:
    """Add evidence-based advisory findings, avoiding assumptions on forks and archives."""
    if repo["disabled"]:
        repo["findings"].append("repository_disabled")
    if not repo["default_branch"] and not repo["archived"]:
        repo["findings"].append("default_branch_missing")
    if not repo["archived"] and not repo["disabled"]:
        pushed = repo["pushed_at"]
        if pushed is None:
            repo["findings"].append("last_push_unavailable")
        elif parse_datetime(pushed) < now - timedelta(days=stale_days):
            repo["findings"].append("last_push_older_than_threshold")


def check_branches(
    repos: List[Dict[str, Any]], opener: urllib.request.OpenerDirector,
    settings: Settings, token: Optional[str], stopped: List[int],
) -> None:
    """Check branch metadata but never infer unverified enforcement from a badge."""
    for index, repo in enumerate(repos, start=1):
        if stopped:
            raise InventoryError("interrupted")
        branch = repo["default_branch"]
        if not branch or repo["archived"] or repo["disabled"]:
            repo["branch_protected"] = "NOT_APPLICABLE"
            continue
        encoded = urllib.parse.quote(branch, safe="")
        url = f"/repos/{settings.organisation}/{repo['name']}/branches/{encoded}"
        try:
            data = read_api(opener, url, settings, token, stopped)
        except InventoryError as exc:
            if str(exc) == "github_http_404":
                repo["branch_protected"] = "NOT_VERIFIED"
                repo["findings"].append("default_branch_metadata_unavailable")
                continue
            raise
        if not isinstance(data, dict) or type(data.get("protected")) is not bool:
            raise InventoryError("github_branch_metadata_invalid")
        repo["branch_protected"] = "REPORTED_TRUE" if data["protected"] else "REPORTED_FALSE"
        if not data["protected"]:
            repo["findings"].append("default_branch_not_reported_protected")
        if index % 25 == 0:
            LOG.info("branches_checked", extra={"data": {"repositories": index}})


def render_markdown(report: Dict[str, Any]) -> str:
    """Render bounded, readable markdown without terminal control sequences."""
    lines = [f"# Organisation inventory: {report['organisation']}", "",
             f"Repositories: {report['repositories_checked']}",
             f"Advisories: {report['advisory_findings']}",
             "", "| Repository | Archived | Private | Branch status | Advisories |",
             "| --- | --- | --- | --- | --- |"]
    for repo in report["repositories"]:
        name = repo["name"].replace("|", "\\|")
        notes = ", ".join(repo["findings"]) or "None"
        lines.append(f"| {name} | {repo['archived']} | {repo['private']} | "
                     f"{repo['branch_protected']} | {notes} |")
    return "\n".join(lines) + "\n"


def _assessment(
    complete: bool, check_default_branches: bool,
    repos: List[Dict[str, Any]], advisory_count: int,
) -> str:
    """Classify evidence truthfully, including unknown branch states."""
    if not complete:
        return "PARTIAL"
    if check_default_branches and any(
        repo["branch_protected"] == "NOT_VERIFIED" or (
            repo["branch_protected"] == "NOT_APPLICABLE"
            and not repo["archived"] and not repo["disabled"]
        ) for repo in repos
    ):
        return "NOT_VERIFIED"
    if check_default_branches and any(
        repo["branch_protected"] == "REPORTED_FALSE" for repo in repos
    ):
        return "UNPROTECTED"
    return "ADVISORY" if advisory_count else "OBSERVED"


def report_inventory(settings: Settings, token: Optional[str], stopped: List[int]) -> int:
    """Run read-only inventory and publish an intentional stdout report."""
    start = time.monotonic()
    now = datetime.now(timezone.utc)
    opener = make_opener()
    repos, pages, complete = collect_repos(opener, settings, token, stopped)
    if not repos:
        raise InventoryError("no_repositories_visible")
    for repo in repos:
        add_risk_flags(repo, now, settings.stale_days)
    if settings.check_branches:
        check_branches(repos, opener, settings, token, stopped)
    advisory_count = sum(len(repo["findings"]) for repo in repos)
    report = {
        "organisation": settings.organisation,
        "scope": "read_only_github_api_inventory_not_security_certification",
        "observed_at": now.isoformat(),
        "repositories_checked": len(repos),
        "pages_checked": pages,
        "complete": complete,
        "assessment": _assessment(complete, settings.check_branches, repos, advisory_count),
        "advisory_findings": advisory_count,
        "repos_with_findings": sum(bool(repo["findings"]) for repo in repos),
        "branches_checked": settings.check_branches,
        "repositories": repos,
    }
    if settings.report_format == "json":
        sys.stdout.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    elif settings.report_format == "markdown":
        sys.stdout.write(render_markdown(report))
    LOG.info("summary", extra={"data": {
        "repositories": len(repos), "pages": pages, "complete": complete, "advisories": advisory_count,
        "duration_seconds": round(time.monotonic() - start, 3),
        "scope": "read_only_non_mutating",
    }})
    if not complete or report["assessment"] == "NOT_VERIFIED":
        return 2
    if report["assessment"] == "UNPROTECTED":
        return 1
    return 1 if settings.strict and advisory_count else 0


def main(argv: Optional[List[str]] = None) -> int:
    """Validate flags, honour signals, and return stable exit codes."""
    args = parse_args(argv)
    configure_logging(args.log_level)
    try:
        settings = validate(args)
    except InventoryError as exc:
        LOG.error("invalid_config", extra={"data": {"reason": str(exc)}})
        return 2
    if settings.dry_run:
        LOG.info("dry_run", extra={"data": {
            "organisation": settings.organisation, "network_requests": 0,
            "filesystem_writes": 0, "subprocesses": 0,
        }})
        return 0
    stopped: List[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        stopped.append(signum)

    started = time.monotonic()
    old_int = signal.signal(signal.SIGINT, handle_signal)
    old_term = signal.signal(signal.SIGTERM, handle_signal)
    try:
        try:
            result = report_inventory(settings, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), stopped)
        except InventoryError as exc:
            LOG.error("inventory_failed", extra={"data": {"reason": str(exc)}})
            result = 2
        if stopped:
            return 130 if stopped[0] == signal.SIGINT else 143
        return result
    finally:
        LOG.info("run_complete", extra={"data": {"duration_seconds": round(time.monotonic() - started, 3)}})
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
