"""Read-only Shards-Kernel operator health probe for cron and service monitors.

Python 3.9+, standard library only; Linux, macOS and Windows.
No permits, tool calls, service restarts, external destinations or writes.
A passing health check is NOT a production-readiness certificate.

Examples:
    python scripts/ops/probe_operator.py --url http://127.0.0.1:8765
    python scripts/ops/probe_operator.py --check-status --expected-kernel-id operator-local
    python scripts/ops/probe_operator.py --checks 0 --interval 30 --log-level INFO
    python scripts/ops/probe_operator.py --check-status --dry-run

When --check-status is set, SHARDS_KERNEL_API_KEY must be injected through
an operator-managed environment. The value is never logged.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

DEFAULT_URL = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT = 5.0
DEFAULT_INTERVAL = 30.0
DEFAULT_ATTEMPTS = 3
MAX_RESPONSE_BYTES = 8192
MAX_BACKOFF_SECONDS = 5.0
MIN_API_KEY_LENGTH = 32
RETRIABLE_HTTP = frozenset({408, 429, 500, 502, 503, 504})
# Authoritative KernelState enum: reject BOOTING, HALTED and unknown values.
# In-flight states remain healthy while work is being processed.
OPERATIONAL_STATES = frozenset({
    "IDLE", "VALIDATING", "ARBITRATING", "EXECUTING", "AUDITING", "COMPLETED",
})
LOG = logging.getLogger("shards.ops.probe")


class ProbeFailure(Exception):
    """Safe, bounded monitoring failure; never includes credentials."""

    def __init__(self, reason: str, *, retriable: bool = False) -> None:
        super().__init__(reason)
        self.retriable = retriable


@dataclass(frozen=True)
class Configuration:
    """Validated settings for a read-only loopback probe."""

    url: str
    timeout: float
    interval: float
    attempts: int
    checks: int
    check_status: bool
    expected_kernel_id: Optional[str]
    dry_run: bool
    api_key: Optional[str]


class JSONFormatter(logging.Formatter):
    """Emit bounded JSON events for unattended log ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "data", {}))
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Deny redirects so credentials never travel to a second origin."""

    def redirect_request(
        self, request: urllib.request.Request, fp: Any, code: int,
        msg: str, headers: Any, newurl: str,
    ) -> None:
        return None


def configure_logging(level: str) -> None:
    """Set single-output structured logging."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.setLevel(getattr(logging, level.upper()))


def parse_url(url: str) -> str:
    """Reject non-loopback origins, embedded credentials and URL extras."""
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid operator URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or not 1 <= (port or 0) <= 65535
        or parsed.path not in {"", "/"}
        or parsed.query or parsed.fragment
    ):
        raise ValueError("Operator URL must be a loopback HTTP(S) origin with an explicit port")
    return url.rstrip("/")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse operator probe arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--checks", type=int, default=1,
                        help="Number of checks, or 0 for continuous monitoring")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="Seconds between checks in continuous or multi-check mode")
    parser.add_argument("--check-status", action="store_true",
                        help="Also read authenticated GET /status")
    parser.add_argument("--expected-kernel-id", default=None,
                        help="Require /status.kernel_id to match this exact value")
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration without network IO")
    parser.add_argument("--log-level", default="INFO",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser.parse_args(argv)


def validate(args: argparse.Namespace, environ: Dict[str, str]) -> Configuration:
    """Validate input before any network operation."""
    import math

    url = parse_url(args.url)
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120:
        raise ValueError("--timeout must be between 0 and 120 seconds")
    if not math.isfinite(args.interval) or not 0 < args.interval <= 86400:
        raise ValueError("--interval must be between 0 and 86400 seconds")
    if not 1 <= args.attempts <= 10:
        raise ValueError("--attempts must be between 1 and 10")
    if not 0 <= args.checks <= 1000000:
        raise ValueError("--checks must be between 0 and 1000000")
    if args.expected_kernel_id is not None and (
        not args.expected_kernel_id or len(args.expected_kernel_id) > 128
        or any(not (char.isalnum() or char in "_.-") for char in args.expected_kernel_id)
    ):
        raise ValueError("--expected-kernel-id must be 1..128 alphanumeric/_.- characters")
    if args.expected_kernel_id and not args.check_status:
        raise ValueError("--expected-kernel-id requires --check-status")
    api_key = environ.get("SHARDS_KERNEL_API_KEY") if args.check_status else None
    if args.check_status and (
        not api_key or len(api_key) < MIN_API_KEY_LENGTH or api_key.strip() != api_key
        or any(not 33 <= ord(char) <= 126 for char in api_key)
    ):
        raise ValueError("--check-status requires a valid SHARDS_KERNEL_API_KEY environment variable")
    return Configuration(
        url, args.timeout, args.interval, args.attempts, args.checks,
        args.check_status, args.expected_kernel_id, args.dry_run, api_key,
    )


def request_json(
    opener: urllib.request.OpenerDirector,
    config: Configuration,
    path: str,
    *,
    authenticated: bool,
) -> Dict[str, Any]:
    """Perform one strictly bounded, read-only HTTP GET."""
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    if authenticated:
        headers["Authorization"] = f"Bearer {config.api_key}"
    request = urllib.request.Request(config.url + path, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=config.timeout) as response:
            if response.status != 200:
                raise ProbeFailure("http_unexpected_status", retriable=response.status in RETRIABLE_HTTP)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ProbeFailure("response_too_large")
    except urllib.error.HTTPError as exc:
        raise ProbeFailure(f"http_{exc.code}", retriable=exc.code in RETRIABLE_HTTP) from None
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        raise ProbeFailure("connection_failure", retriable=True) from None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeFailure("invalid_json") from None
    if not isinstance(payload, dict):
        raise ProbeFailure("invalid_json_shape")
    return payload


def probe_once(config: Configuration, stop: threading.Event) -> None:
    """Retry transient transport failures, never unsafe or malformed responses."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for attempt in range(1, config.attempts + 1):
        if stop.is_set():
            raise ProbeFailure("interrupted")
        try:
            health = request_json(opener, config, "/health", authenticated=False)
            health_state = health.get("kernel_state")
            if (health.get("status") != "healthy"
                    or not isinstance(health_state, str)
                    or health_state not in OPERATIONAL_STATES):
                raise ProbeFailure("unhealthy_kernel")
            if config.check_status:
                status = request_json(opener, config, "/status", authenticated=True)
                status_state = status.get("state")
                if (not isinstance(status.get("kernel_id"), str)
                        or not status["kernel_id"]
                        or not isinstance(status_state, str)
                        or status_state not in OPERATIONAL_STATES):
                    raise ProbeFailure("invalid_kernel_status")
                if config.expected_kernel_id and status["kernel_id"] != config.expected_kernel_id:
                    raise ProbeFailure("wrong_kernel_identity")
            return
        except ProbeFailure as exc:
            if not exc.retriable or attempt == config.attempts:
                raise
            delay = min(MAX_BACKOFF_SECONDS, float(2 ** (attempt - 1)))
            LOG.warning("probe_retry", extra={"data": {"attempt": attempt, "reason": str(exc)}})
            stop.wait(delay)
    raise ProbeFailure("attempts_exhausted")


def run(config: Configuration, stop: threading.Event) -> int:
    """Run bounded or continuous checks and emit a final summary."""
    started = time.monotonic()
    passed = 0
    failed = 0
    reason = "ok"
    if config.dry_run:
        LOG.info("dry_run", extra={"data": {
            "url": config.url, "checks": config.checks, "authenticated_status": config.check_status,
            "scope": "read_only_loopback_probe", "network_calls": 0,
        }})
        return 0
    try:
        while not stop.is_set() and (config.checks == 0 or passed + failed < config.checks):
            try:
                probe_once(config, stop)
                passed += 1
                LOG.info("probe_pass", extra={"data": {"check": passed + failed}})
            except ProbeFailure as exc:
                if stop.is_set():
                    reason = "interrupted"
                else:
                    failed += 1
                    reason = str(exc)
                    LOG.error("probe_failed", extra={"data": {"reason": reason}})
                break
            if config.checks == 0 or passed + failed < config.checks:
                stop.wait(config.interval)
    finally:
        LOG.info("summary", extra={"data": {
            "passed": passed, "failed": failed,
            "duration_seconds": round(time.monotonic() - started, 3),
            "result": "INTERRUPTED" if stop.is_set() else "FAILED" if failed else "HEALTHY",
            "scope": "local_process_health_only_not_production_readiness",
            "reason": reason,
        }})
    return 1 if failed else 0


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint with defined exit codes and signal handling."""
    args = parse_args(argv)
    configure_logging(args.log_level)
    try:
        config = validate(args, dict(os.environ))
    except ValueError as exc:
        LOG.error("configuration_rejected", extra={"data": {"reason": str(exc)}})
        return 2
    stop = threading.Event()
    exit_signal: list[int] = []

    def handle_signal(signum: int, _frame: Any) -> None:
        exit_signal.append(signum)
        stop.set()

    previous_interrupt = signal.signal(signal.SIGINT, handle_signal)
    previous_term = None
    if hasattr(signal, "SIGTERM"):
        previous_term = signal.signal(signal.SIGTERM, handle_signal)
    try:
        result = run(config, stop)
    finally:
        signal.signal(signal.SIGINT, previous_interrupt)
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)
    if exit_signal:
        return 130 if exit_signal[0] == signal.SIGINT else 143
    return result


if __name__ == "__main__":
    sys.exit(main())
