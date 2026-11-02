"""
Shards-Kernel SDK Server

HTTP server for exposing kernel functionality.
"""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Type
import threading

from shards_kernel._version import __version__
from shards_kernel.common.types import VirtualClock
from shards_kernel.integrations.auth import bearer_authorized, resolve_api_key
from shards_kernel.integrations.wire import (
    boot_service_kernel,
    evidence_to_mapping,
    policy_to_mapping,
    receipt_to_mapping,
    request_from_mapping,
    status_mapping,
)
from shards_kernel.variants.base import BaseKernel
from shards_kernel.jurisdiction.policy import JurisdictionPolicy


class KernelRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for kernel server."""

    # Class-level kernel reference (set by server)
    kernel: Optional[BaseKernel] = None
    api_key: Optional[str] = None
    trusted_actor: Optional[str] = None  # Enforced for operator-managed services
    max_body_bytes: int = 1024 * 1024

    def _authorized(self) -> bool:
        if self.api_key and bearer_authorized(self.headers.get("Authorization"), self.api_key):
            return True
        self._send_json(401, {"error": "Unauthorized"})
        return False

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _read_json(self) -> Dict[str, Any]:
        """Read JSON from request body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid Content-Length") from exc
        if content_length < 0:
            raise ValueError("Invalid Content-Length")
        if content_length > self.max_body_bytes:
            raise OverflowError("Request body too large")
        body = self.rfile.read(content_length)
        return json.loads(body.decode("utf-8")) if body else {}

    def do_OPTIONS(self) -> None:
        """No cross-origin browser access by default."""
        self._send_json(405, {"error": "CORS preflight not enabled"})

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path in {"/status", "/evidence", "/policy"} and not self._authorized():
            return
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/status":
            self._handle_status()
        elif self.path == "/evidence":
            self._handle_evidence()
        elif self.path == "/policy":
            self._handle_policy()
        elif self.path == "/":
            self._handle_info()
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path in {"/submit", "/halt"} and not self._authorized():
            return
        if self.path == "/submit":
            self._handle_submit()
        elif self.path == "/halt":
            self._handle_halt()
        else:
            self._send_json(404, {"error": "Not found"})

    def _handle_info(self) -> None:
        """Handle info request."""
        self._send_json(
            200,
            {
                "name": "Shards-Kernel",
                "version": __version__,
                "kernel_id": self.kernel.config.kernel_id if self.kernel else None,
            },
        )

    def _handle_health(self) -> None:
        """Handle health check."""
        if not self.kernel:
            self._send_json(503, {"status": "unhealthy", "error": "No kernel"})
            return

        try:
            state = self.kernel.get_state()
            # A process is not healthy merely because its HTTP socket listens.
            self.kernel.config.clock.now_ms()
            if state.value == "HALTED":
                raise RuntimeError("Kernel is halted")
        except Exception:
            self._send_json(503, {"status": "unhealthy"})
            return

        self._send_json(
            200,
            {
                "status": "healthy",
                "kernel_state": state.value,
            },
        )

    def _handle_status(self) -> None:
        """Handle status request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self._send_json(200, status_mapping(self.kernel))

    def _handle_evidence(self) -> None:
        """Handle evidence export."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self._send_json(200, evidence_to_mapping(self.kernel.export_evidence()))

    def _handle_policy(self) -> None:
        """Handle policy request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self._send_json(200, policy_to_mapping(self.kernel))

    def _handle_submit(self) -> None:
        """Handle request submission."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        try:
            data = self._read_json()
            # A caller may not claim an arbitrary principal when the service
            # API key is bound to one operator-configured local agent.
            if self.trusted_actor is not None and data.get("actor") != self.trusted_actor:
                self._send_json(403, {"error": "Caller identity does not match service principal"})
                return

            request, permit = request_from_mapping(self.kernel, data)
            receipt = self.kernel.submit(request, permit_token=permit)
            self._send_json(200, receipt_to_mapping(receipt))

        except KeyError as e:
            self._send_json(400, {"error": f"Missing field: {e}"})
        except (ValueError, TypeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Malformed JSON request"})
        except OverflowError:
            self._send_json(413, {"error": "Request body too large"})
        except Exception:
            self._send_json(500, {"error": "Internal server error"})

    def _handle_halt(self) -> None:
        """Handle halt request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self.kernel.halt("operator halt")
        self._send_json(
            200,
            {
                "status": "halted",
                "kernel_state": self.kernel.get_state().value,
            },
        )

    def log_message(self, format: str, *args) -> None:
        """Override to customize logging."""
        pass  # Suppress default logging


class KernelServer:
    """
    HTTP server for Shards-Kernel.

    Exposes kernel functionality via REST API.

    Example:
        kernel = StrictKernel()
        server = KernelServer(kernel, port=8080)
        server.start()
    """

    def __init__(
        self,
        kernel: BaseKernel,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        api_key: Optional[str] = None,
        allow_remote_bind: bool = False,
        allow_test_clock: bool = False,
        trusted_actor: Optional[str] = None,
    ):
        if isinstance(kernel.config.clock, VirtualClock) and not allow_test_clock:
            raise ValueError(
                "Frozen VirtualClock cannot be used for HTTP permit expiry; "
                "use a real SystemClock or explicitly allow_test_clock=True for tests"
            )
        if host not in {"localhost", "127.0.0.1", "::1"} and not allow_remote_bind:
            raise ValueError("Remote HTTP binding requires explicit allow_remote_bind=True and a secure TLS ingress")
        if trusted_actor is not None and (
            not isinstance(trusted_actor, str)
            or not trusted_actor
            or "*" in trusted_actor
            or trusted_actor not in kernel.policy.allowed_actors
        ):
            raise ValueError("Trusted actor must be explicitly present in kernel policy")
        self.api_key = resolve_api_key(api_key)
        self.trusted_actor = trusted_actor
        self.kernel = kernel
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _create_handler(self) -> Type[KernelRequestHandler]:
        """Create handler class with kernel reference."""
        kernel = self.kernel

        class Handler(KernelRequestHandler):
            pass

        Handler.kernel = kernel
        Handler.api_key = self.api_key
        Handler.trusted_actor = self.trusted_actor
        return Handler

    def start(self, blocking: bool = True) -> None:
        """
        Start the server.

        Args:
            blocking: If True, block until server stops.
                     If False, run in background thread.
        """
        handler = self._create_handler()
        self._server = HTTPServer((self.host, self.port), handler)

        if blocking:
            print(f"Shards-Kernel server running on http://{self.host}:{self.port}")
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever)
            self._thread.daemon = True
            self._thread.start()
            print(f"Shards-Kernel server started on http://{self.host}:{self.port}")

    def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def url(self) -> str:
        """Get server URL."""
        return f"http://{self.host}:{self.port}"


def run_server(
    kernel_id: str = "server-001",
    host: str = "127.0.0.1",
    port: int = 8080,
    policy: Optional[JurisdictionPolicy] = None,
    api_key: Optional[str] = None,
    allow_remote_bind: bool = False,
) -> None:
    """
    Convenience function to run a kernel server.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy (uses default if not specified)
    """
    kernel = boot_service_kernel(kernel_id)
    if policy is not None:
        kernel.set_policy(policy)
    server = KernelServer(
        kernel, host, port, api_key=api_key, allow_remote_bind=allow_remote_bind
    )

    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    run_server()
