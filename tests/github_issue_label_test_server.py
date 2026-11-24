"""Real local HTTP GitHub-API subset for provider integration tests.

This is a test *provider*, not a fake kernel. The production provider builds
its exact GitHub request path and sends it through a transport that routes
``https://api.github.com`` to this loopback server. Every request is recorded
so tests can assert that a label was (or was not) written.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from shards_kernel.providers.github_issue_label import HttpResponse


class _Handler(BaseHTTPRequestHandler):
    server_version = "GitHubTestProvider/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _state(self) -> "GitHubTestProvider":
        return self.server.state  # type: ignore[attr-defined]

    def _send(self, status: int, payload: Any = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _record(self) -> bytes:
        state = self._state()
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        with state.lock:
            state.requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "body": body,
                    "authorization": self.headers.get("Authorization"),
                }
            )
            state.token_seen.append(self.headers.get("Authorization"))
        return body

    def do_GET(self) -> None:  # noqa: N802
        state = self._state()
        self._record()
        with state.lock:
            state.get_count += 1
            issue = state.issue_from_path(urllib.parse.urlsplit(self.path).path)
            present = issue is not None and issue in state.labels
            names = sorted(state.labels[issue]) if present else []
        if state.get_status is not None:
            self._send(state.get_status, {"message": "injected"})
            return
        if issue is None or not present:
            self._send(404, {"message": "Not Found"})
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        per_page = min(int(query.get("per_page", ["100"])[0]), 100)
        page = max(int(query.get("page", ["1"])[0]), 1)
        start = (page - 1) * per_page
        chunk = names[start : start + per_page]
        if state.malformed_readback:
            self._send(200, {"not": "a list"})
            return
        self._send(200, [{"name": name} for name in chunk])

    def do_POST(self) -> None:  # noqa: N802
        state = self._state()
        body = self._record()
        with state.lock:
            state.post_count += 1
            issue = state.issue_from_path(urllib.parse.urlsplit(self.path).path)
            present = issue is not None and issue in state.labels
        if issue is None or not present:
            self._send(404, {"message": "Not Found"})
            return
        try:
            payload = json.loads(body)
            labels = payload["labels"]
            assert isinstance(labels, list) and len(labels) == 1
            label = labels[0]
            assert isinstance(label, str)
        except Exception:
            self._send(422, {"message": "Validation Failed"})
            return
        if state.drop_connection_after_post:
            self.close_connection = True
            return
        if state.delay_seconds_after_post:
            time.sleep(state.delay_seconds_after_post)
        if state.apply_then_status is not None:
            with state.lock:
                state.labels[issue].add(label)
                names = sorted(state.labels[issue])
            self._send(state.apply_then_status, {"message": "applied-then-error"})
            return
        if state.post_status is not None:
            self._send(state.post_status, {"message": "injected"})
            return
        with state.lock:
            state.labels[issue].add(label)
            names = sorted(state.labels[issue])
        self._send(200, [{"name": name} for name in names])


class GitHubTestProvider:
    """Loopback GitHub API subset with injectable failures."""

    def __init__(self, *, token: str = "ghp_test_provider_token_0123456789") -> None:
        self.token = token
        self.labels: dict[int, set[str]] = {}
        self.requests: list[dict[str, Any]] = []
        self.token_seen: list[Optional[str]] = []
        self.post_count = 0
        self.get_count = 0
        self.post_status: Optional[int] = None
        self.get_status: Optional[int] = None
        self.apply_then_status: Optional[int] = None
        self.delay_seconds_after_post: float = 0.0
        self.drop_connection_after_post = False
        self.malformed_readback = False
        self.lock = threading.Lock()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def add_issue(self, issue: int, labels: Optional[set[str]] = None) -> None:
        with self.lock:
            self.labels[issue] = set(labels or ())

    def issue_from_path(self, path: str) -> Optional[int]:
        parts = path.strip("/").split("/")
        # repos/<owner>/<repo>/issues/<number>/labels
        if (
            len(parts) != 6
            or parts[0] != "repos"
            or parts[3] != "issues"
            or parts[5] != "labels"
        ):
            return None
        try:
            return int(parts[4])
        except ValueError:
            return None

    def start(self) -> "GitHubTestProvider":
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        httpd.daemon_threads = True
        httpd.state = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("test provider is not running")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def post_bodies(self) -> list[bytes]:
        with self.lock:
            return [r["body"] for r in self.requests if r["method"] == "POST"]


class LoopbackTransport:
    """Route the provider's production URL to the loopback test provider."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(
        self,
        method: str,
        url: str,
        headers: Any,
        body: Optional[bytes],
        timeout: float,
    ) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise AssertionError("provider attempted a non-production API URL")
        target = self.base_url + parsed.path
        if parsed.query:
            target += "?" + parsed.query
        request = urllib.request.Request(
            target, data=body, headers=dict(headers), method=method
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return HttpResponse(
                    status=int(response.status),
                    body=response.read(1024 * 1024),
                    headers=dict(response.headers),
                )
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read(1024 * 1024)
            except Exception:
                payload = b""
            return HttpResponse(status=int(exc.code), body=payload, headers={})
        except Exception as exc:
            raise RuntimeError(type(exc).__name__) from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None
