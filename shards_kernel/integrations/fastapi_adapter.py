"""
Shards-Kernel FastAPI Integration

Provides FastAPI app factory for kernel servers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, Depends, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

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


if HAS_FASTAPI:

    class ToolCallModel(BaseModel):
        """Tool call request model."""

        name: str
        params: Dict[str, Any] = {}

    class SubmitRequest(BaseModel):
        """Request submission model."""

        request_id: str
        actor: str
        intent: str
        tool_call: Optional[ToolCallModel] = None
        params: Optional[Dict[str, Any]] = None
        evidence: Optional[Any] = None
        permit: Optional[Dict[str, Any]] = None

    class ReceiptResponse(BaseModel):
        """Receipt response model."""

        request_id: str
        status: str
        decision: str
        result: Optional[Any] = None
        error: Optional[str] = None

    class HealthResponse(BaseModel):
        """Health check response."""

        status: str
        kernel_state: str

    class StatusResponse(BaseModel):
        """Status response."""

        kernel_id: str
        state: str

    class EvidenceResponse(BaseModel):
        """Evidence export response."""

        kernel_id: str
        exported_at: int
        ledger_entries: List[Dict[str, Any]]
        root_hash: str
        entry_count: int


def create_fastapi_app(
    kernel: Optional[BaseKernel] = None,
    kernel_id: str = "fastapi-kernel",
    policy: Optional[JurisdictionPolicy] = None,
    title: str = "Shards-Kernel API",
    version: str = "0.1.0",
    cors_origins: Optional[List[str]] = None,
    api_key: Optional[str] = None,
    allow_test_clock: bool = False,
) -> "FastAPI":
    """
    Create a FastAPI app for the kernel.

    Args:
        kernel: Existing kernel to use (creates new if None)
        kernel_id: Kernel ID if creating new kernel
        policy: Policy for new kernel
        title: API title
        version: API version
        cors_origins: Allowed CORS origins

    Returns:
        FastAPI app instance
    """
    if not HAS_FASTAPI:
        raise ImportError("FastAPI not installed. Run: pip install fastapi uvicorn")
    secret = resolve_api_key(api_key)

    # Create kernel if not provided
    if kernel is None:
        kernel = boot_service_kernel(kernel_id)
        if policy is not None:
            kernel.set_policy(policy)

    if isinstance(kernel.config.clock, VirtualClock) and not allow_test_clock:
        raise ValueError("Frozen VirtualClock is not safe for service permit expiry")

    # Create app
    app = FastAPI(
        title=title,
        version=version,
        description="Shards-Kernel - Deterministic Control Plane for AI Systems",
    )

    # Cross-origin browser access is opt-in and must be restricted at the edge.
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    def authenticate(request: Request) -> None:
        if not bearer_authorized(request.headers.get("Authorization"), secret):
            raise HTTPException(status_code=401, detail="Unauthorized")

    # Store kernel in app state
    app.state.kernel = kernel

    def get_kernel() -> BaseKernel:
        return app.state.kernel

    @app.get("/", tags=["Info"])
    async def info():
        """Get API info."""
        return {
            "name": "Shards-Kernel",
            "version": version,
            "kernel_id": kernel.config.kernel_id,
        }

    @app.get("/health", response_model=HealthResponse, tags=["Health"])
    async def health(k: BaseKernel = Depends(get_kernel)):
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            kernel_state=k.get_state().value,
        )

    @app.get("/status", response_model=StatusResponse, tags=["Status"], dependencies=[Depends(authenticate)])
    async def status(k: BaseKernel = Depends(get_kernel)):
        """Get kernel status."""
        current = status_mapping(k)
        return StatusResponse(
            kernel_id=current["kernel_id"],
            state=current["state"],
        )

    @app.post("/submit", response_model=ReceiptResponse, tags=["Requests"], dependencies=[Depends(authenticate)])
    async def submit(
        body: SubmitRequest,
        k: BaseKernel = Depends(get_kernel),
    ):
        """Submit a request to the kernel."""
        payload = body.model_dump() if hasattr(body, "model_dump") else body.dict()
        if payload.get("tool_call") is not None:
            payload["tool_call"] = {
                "name": body.tool_call.name,
                "params": body.tool_call.params,
            }
        try:
            request, permit = request_from_mapping(k, payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Malformed request") from exc
        receipt = k.submit(request, permit_token=permit)
        mapped = receipt_to_mapping(receipt)
        return ReceiptResponse(
            request_id=mapped["request_id"],
            status=mapped["status"],
            decision=mapped["decision"],
            result=mapped["result"],
            error=mapped["error"],
        )

    @app.get("/evidence", tags=["Audit"], dependencies=[Depends(authenticate)])
    async def evidence(k: BaseKernel = Depends(get_kernel)):
        """Export audit evidence."""
        return evidence_to_mapping(k.export_evidence())

    @app.get("/policy", tags=["Policy"], dependencies=[Depends(authenticate)])
    async def policy(k: BaseKernel = Depends(get_kernel)):
        """Get current policy."""
        return policy_to_mapping(k)

    @app.post("/halt", tags=["Control"], dependencies=[Depends(authenticate)])
    async def halt(k: BaseKernel = Depends(get_kernel)):
        """Halt the kernel."""
        k.halt("operator halt")
        return {
            "status": "halted",
            "kernel_state": k.get_state().value,
        }

    return app


def run_fastapi_server(
    kernel_id: str = "fastapi-kernel",
    host: str = "127.0.0.1",
    port: int = 8080,
    policy: Optional[JurisdictionPolicy] = None,
    api_key: Optional[str] = None,
    allow_remote_bind: bool = False,
) -> None:
    """
    Run FastAPI server with uvicorn.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy
    """
    try:
        import uvicorn
    except ImportError:
        raise ImportError("uvicorn not installed. Run: pip install uvicorn")

    if host not in {"localhost", "127.0.0.1", "::1"} and not allow_remote_bind:
        raise ValueError("Remote binding requires explicit allow_remote_bind=True and a secure TLS ingress")
    app = create_fastapi_app(kernel_id=kernel_id, policy=policy, api_key=api_key)
    uvicorn.run(app, host=host, port=port)
