"""
Shards-Kernel Flask Integration

Provides Flask app factory for kernel servers.
"""

from __future__ import annotations

from typing import Optional

try:
    from flask import Flask, request, jsonify

    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

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


def create_flask_app(
    kernel: Optional[BaseKernel] = None,
    kernel_id: str = "flask-kernel",
    policy: Optional[JurisdictionPolicy] = None,
) -> "Flask":
    """
    Create a Flask app for the kernel.

    Args:
        kernel: Existing kernel to use (creates new if None)
        kernel_id: Kernel ID if creating new kernel
        policy: Policy for new kernel

    Returns:
        Flask app instance
    """
    if not HAS_FLASK:
        raise ImportError("Flask not installed. Run: pip install flask")

    # Create kernel if not provided
    if kernel is None:
        kernel = boot_strict_kernel(kernel_id)
        if policy is not None:
            kernel.set_policy(policy)

    # Create app
    app = Flask(__name__)
    app.config["kernel"] = kernel

    @app.route("/", methods=["GET"])
    def info():
        """Get API info."""
        return jsonify(
            {
                "name": "Shards-Kernel",
                "version": "0.1.0",
                "kernel_id": app.config["kernel"].config.kernel_id,
            }
        )

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        k = app.config["kernel"]
        return jsonify(
            {
                "status": "healthy",
                "kernel_state": k.get_state().value,
            }
        )

    @app.route("/status", methods=["GET"])
    def status():
        """Get kernel status."""
        k = app.config["kernel"]
        return jsonify(status_mapping(k))

    @app.route("/submit", methods=["POST"])
    def submit():
        """Submit a request to the kernel."""
        k = app.config["kernel"]
        data = request.get_json()

        request_obj, permit = request_from_mapping(k, data or {})
        receipt = k.submit(request_obj, permit_token=permit)
        return jsonify(receipt_to_mapping(receipt))

    @app.route("/evidence", methods=["GET"])
    def evidence():
        """Export audit evidence."""
        k = app.config["kernel"]
        return jsonify(evidence_to_mapping(k.export_evidence()))

    @app.route("/policy", methods=["GET"])
    def policy():
        """Get current policy."""
        k = app.config["kernel"]
        return jsonify(policy_to_mapping(k))

    @app.route("/halt", methods=["POST"])
    def halt():
        """Halt the kernel."""
        k = app.config["kernel"]
        k.halt("operator halt")
        return jsonify(
            {
                "status": "halted",
                "kernel_state": k.get_state().value,
            }
        )

    return app


def run_flask_server(
    kernel_id: str = "flask-kernel",
    host: str = "127.0.0.1",
    port: int = 8080,
    policy: Optional[JurisdictionPolicy] = None,
    debug: bool = False,
) -> None:
    """
    Run Flask server.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy
        debug: Deprecated. Debug mode is disabled for security hardening.
    """
    app = create_flask_app(kernel_id=kernel_id, policy=policy)
    if debug:
        raise ValueError(
            "Debug mode is disabled for security; run behind a proper debugger."
        )
    app.run(host=host, port=port)
