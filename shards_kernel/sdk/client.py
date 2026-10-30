"""
Shards-Kernel SDK Client

HTTP client for interacting with Shards-Kernel servers.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import asyncio

from shards_kernel.common.types import Decision, KernelState, Receipt, ReceiptStatus, Request
from shards_kernel.common.errors import KernelError
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.permits import PermitToken


@dataclass
class ClientConfig:
    """Configuration for kernel client."""

    base_url: str = "http://localhost:8080"
    timeout: float = 30.0
    api_key: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    retry_count: int = 3
    retry_backoff: float = 1.0


class KernelClient:
    """
    Synchronous HTTP client for Shards-Kernel.

    Provides methods for submitting requests, checking status,
    and exporting evidence.

    Example:
        client = KernelClient("http://localhost:8080")
        receipt = client.submit(request)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self._validate_http_url(base_url)
        self.config = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            timeout=timeout,
        )

    @staticmethod
    def _validate_http_url(url: str) -> None:
        """Reject non-HTTP(S) URLs and embedded credentials."""
        try:
            parsed = urllib.parse.urlsplit(url)
            hostname = parsed.hostname
        except ValueError as exc:
            raise ValueError(f"Invalid kernel server URL: {exc}") from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("Kernel server URL must be an HTTP(S) URL without credentials or fragments")

    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make HTTP request to kernel server."""
        url = f"{self.config.base_url}{path}"
        try:
            self._validate_http_url(url)
        except ValueError as exc:
            raise KernelError(str(exc)) from exc

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        if self.config.headers:
            headers.update(self.config.headers)

        body = json.dumps(data).encode("utf-8") if data else None

        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:  # nosec B310: URL is validated as HTTP(S) above
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise KernelError(f"HTTP {e.code}: {error_body}")
        except urllib.error.URLError as e:
            raise KernelError(f"Connection error: {e.reason}")

    def submit(
        self,
        request: Request,
        permit_token: Optional[PermitToken] = None,
    ) -> Receipt:
        """
        Submit a request to the kernel.

        Args:
            request: The request to submit.
            permit_token: Permit authorising a tool call, when one is required.

        Returns:
            Receipt with decision and result.
        """
        data: Dict[str, Any] = {
            "request_id": request.request_id,
            "ts_ms": request.ts_ms,
            "actor": request.actor,
            "intent": request.intent,
            "params": request.params,
        }

        if request.tool_call:
            data["tool_call"] = {
                "name": request.tool_call.name,
                "params": request.tool_call.params,
            }

        if request.evidence:
            data["evidence"] = request.evidence

        if permit_token is not None:
            data["permit"] = permit_to_mapping(permit_token)

        response = self._make_request("POST", "/submit", data)

        return Receipt(
            request_id=response["request_id"],
            status=ReceiptStatus(response["status"]),
            state_from=KernelState(response.get("state_from", "IDLE")),
            state_to=KernelState(response.get("state_to", "IDLE")),
            ts_ms=int(response.get("ts_ms", 0)),
            decision=Decision[response["decision"]],
            error=response.get("error"),
            evidence_hash=response.get("evidence_hash"),
            tool_result=response.get("result"),
        )

    def submit_batch(self, requests: List[Request]) -> List[Receipt]:
        """
        Submit multiple requests.

        Args:
            requests: List of requests to submit

        Returns:
            List of receipts in same order
        """
        return [self.submit(req) for req in requests]

    def health(self) -> Dict[str, Any]:
        """
        Check kernel health.

        Returns:
            Health status dict
        """
        return self._make_request("GET", "/health")

    def status(self) -> Dict[str, Any]:
        """
        Get kernel status.

        Returns:
            Status dict with kernel state
        """
        return self._make_request("GET", "/status")

    def evidence(self) -> Dict[str, Any]:
        """
        Export audit evidence.

        Returns:
            Evidence bundle
        """
        return self._make_request("GET", "/evidence")

    def halt(self) -> Dict[str, Any]:
        """
        Halt the kernel.

        Returns:
            Confirmation dict
        """
        return self._make_request("POST", "/halt")

    def policy(self) -> Dict[str, Any]:
        """
        Get current policy.

        Returns:
            Policy configuration
        """
        return self._make_request("GET", "/policy")


class AsyncKernelClient:
    """
    Async HTTP client for Shards-Kernel.

    Provides async methods for submitting requests.
    Uses asyncio for non-blocking I/O.

    Example:
        client = AsyncKernelClient("http://localhost:8080")
        receipt = await client.submit(request)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.config = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            timeout=timeout,
        )
        self._sync_client = KernelClient(base_url, api_key, timeout)

    async def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make async HTTP request."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._sync_client._make_request,
            method,
            path,
            data,
        )

    async def submit(
        self,
        request: Request,
        permit_token: Optional[PermitToken] = None,
    ) -> Receipt:
        """Submit a request to the kernel."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._sync_client.submit(request, permit_token=permit_token),
        )

    async def submit_batch(
        self,
        requests: List[Request],
        concurrency: int = 10,
    ) -> List[Receipt]:
        """
        Submit multiple requests with controlled concurrency.

        Args:
            requests: List of requests to submit
            concurrency: Maximum concurrent requests

        Returns:
            List of receipts in same order
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def submit_with_semaphore(req: Request) -> Receipt:
            async with semaphore:
                return await self.submit(req)

        tasks = [submit_with_semaphore(req) for req in requests]
        return await asyncio.gather(*tasks)

    async def health(self) -> Dict[str, Any]:
        """Check kernel health."""
        return await self._make_request("GET", "/health")

    async def status(self) -> Dict[str, Any]:
        """Get kernel status."""
        return await self._make_request("GET", "/status")

    async def evidence(self) -> Dict[str, Any]:
        """Export audit evidence."""
        return await self._make_request("GET", "/evidence")

    async def halt(self) -> Dict[str, Any]:
        """Halt the kernel."""
        return await self._make_request("POST", "/halt")


# Convenience functions


def create_client(
    url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
) -> KernelClient:
    """Create a synchronous kernel client."""
    return KernelClient(url, api_key)


def create_async_client(
    url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
) -> AsyncKernelClient:
    """Create an async kernel client."""
    return AsyncKernelClient(url, api_key)
