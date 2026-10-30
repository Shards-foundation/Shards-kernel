"""
Shards-Kernel SDK Server

HTTP server for exposing kernel functionality.
"""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Type
import threading

from shards_kernel.integrations.wire import (
    boot_strict_kernel,
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

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _read_json(self) -> Dict[str, Any]:
        """Read JSON from request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        return json.loads(body.decode("utf-8")) if body else {}

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests."""
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
                "version": "0.1.0",
                "kernel_id": self.kernel.config.kernel_id if self.kernel else None,
            },
        )

    def _handle_health(self) -> None:
        """Handle health check."""
        if not self.kernel:
            self._send_json(503, {"status": "unhealthy", "error": "No kernel"})
            return

        self._send_json(
            200,
            {
                "status": "healthy",
                "kernel_state": self.kernel.get_state().value,
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

            request, permit = request_from_mapping(self.kernel, data)
            receipt = self.kernel.submit(request, permit_token=permit)
            self._send_json(200, receipt_to_mapping(receipt))

        except KeyError as e:
            self._send_json(400, {"error": f"Missing field: {e}"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

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
    ):
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
) -> None:
    """
    Convenience function to run a kernel server.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy (uses default if not specified)
    """
    kernel = boot_strict_kernel(kernel_id)
    if policy is not None:
        kernel.set_policy(policy)
    server = KernelServer(kernel, host, port)

    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    run_server()
