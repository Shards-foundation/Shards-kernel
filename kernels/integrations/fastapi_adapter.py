"""
KERNELS FastAPI Integration

Provides FastAPI app factory for kernel servers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from kernels.integrations.wire import (
    boot_strict_kernel,
    evidence_to_mapping,
    policy_to_mapping,
    receipt_to_mapping,
    request_from_mapping,
    status_mapping,
)
from kernels.variants.base import BaseKernel
from kernels.jurisdiction.policy import JurisdictionPolicy


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
    title: str = "KERNELS API",
    version: str = "0.1.0",
    cors_origins: List[str] = ["*"],
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

    # Create kernel if not provided
    if kernel is None:
        kernel = boot_strict_kernel(kernel_id)
        if policy is not None:
            kernel.set_policy(policy)

    # Create app
    app = FastAPI(
        title=title,
        version=version,
        description="KERNELS - Deterministic Control Plane for AI Systems",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store kernel in app state
    app.state.kernel = kernel

    def get_kernel() -> BaseKernel:
        return app.state.kernel

    @app.get("/", tags=["Info"])
    async def info():
        """Get API info."""
        return {
            "name": "KERNELS",
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

    @app.get("/status", response_model=StatusResponse, tags=["Status"])
    async def status(k: BaseKernel = Depends(get_kernel)):
        """Get kernel status."""
        current = status_mapping(k)
        return StatusResponse(
            kernel_id=current["kernel_id"],
            state=current["state"],
        )

    @app.post("/submit", response_model=ReceiptResponse, tags=["Requests"])
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
        request, permit = request_from_mapping(k, payload)
        receipt = k.submit(request, permit_token=permit)
        mapped = receipt_to_mapping(receipt)
        return ReceiptResponse(
            request_id=mapped["request_id"],
            status=mapped["status"],
            decision=mapped["decision"],
            result=mapped["result"],
            error=mapped["error"],
        )

    @app.get("/evidence", tags=["Audit"])
    async def evidence(k: BaseKernel = Depends(get_kernel)):
        """Export audit evidence."""
        return evidence_to_mapping(k.export_evidence())

    @app.get("/policy", tags=["Policy"])
    async def policy(k: BaseKernel = Depends(get_kernel)):
        """Get current policy."""
        return policy_to_mapping(k)

    @app.post("/halt", tags=["Control"])
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

    app = create_fastapi_app(kernel_id=kernel_id, policy=policy)
    uvicorn.run(app, host=host, port=port)
