"""Adapters, the async wrapper, and halt irrevocability."""

from __future__ import annotations

import json
import unittest
import urllib.request

from kernels.common.errors import StateError
from kernels.common.types import (
    Decision,
    KernelConfig,
    KernelRequest,
    KernelState,
    ToolCall,
    VirtualClock,
)
from kernels.integrations.mcp_adapter import MCPAdapter, MCPToolCall
from kernels.integrations.wire import permit_to_mapping
from kernels.permits import PermitBuilder
from kernels.sdk.client import KernelClient
from kernels.sdk.server import KernelServer
from kernels.state.machine import StateMachine
from kernels.variants.strict_kernel import StrictKernel

try:
    from fastapi.testclient import TestClient

    from kernels.integrations.fastapi_adapter import create_fastapi_app

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    import flask  # noqa: F401

    from kernels.integrations.flask_adapter import create_flask_app

    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


KEYRING = {"key1": b"test-secret-key-32-bytes-long123"}


def _kernel() -> StrictKernel:
    kernel = StrictKernel()
    kernel.boot(
        KernelConfig(kernel_id="adapter", variant="strict", clock=VirtualClock(1000))
    )
    kernel.set_keyring(KEYRING)
    return kernel


def _permit(action: str, params: dict, subject: str = "alice") -> object:
    return (
        PermitBuilder()
        .issuer("operator")
        .subject(subject)
        .jurisdiction("default")
        .action(action)
        .params(params)
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10_000)
        .evidence_hash("e")
        .proposal_hash("p")
        .build(KEYRING, "key1")
    )


def _body(params: dict, permit: object | None, request_id: str = "req") -> dict:
    payload = {
        "request_id": request_id,
        "ts_ms": 1000,
        "actor": "alice",
        "intent": "Echo through the adapter",
        "tool_call": {"name": "echo", "params": params},
        "params": params,
    }
    if permit is not None:
        payload["permit"] = permit_to_mapping(permit)  # type: ignore[arg-type]
    return payload


class _AdapterCases:
    """Shared allow / deny checks. Subclasses post JSON and return a dict."""

    kernel: StrictKernel

    def post(self, payload: dict) -> dict:
        raise NotImplementedError

    def test_valid_permit_runs_the_tool(self) -> None:
        params = {"text": "hello"}
        body = self.post(_body(params, _permit("echo", params), "ok"))
        self.assertEqual(body["decision"], "ALLOW")  # type: ignore[attr-defined]
        self.assertEqual(body["result"], "hello")

    def test_missing_permit_is_denied(self) -> None:
        body = self.post(_body({"text": "hello"}, None, "missing"))
        self.assertEqual(body["decision"], "DENY")  # type: ignore[attr-defined]
        self.assertIn("MISSING_PERMIT", body["error"])

    def test_mismatched_params_are_denied(self) -> None:
        permit = _permit("echo", {"text": "hello"})
        payload = _body({"text": "other"}, permit, "mismatch")
        body = self.post(payload)
        self.assertEqual(body["decision"], "DENY")  # type: ignore[attr-defined]
        self.assertIn("PARAM", body["error"])


@unittest.skipUnless(HAS_FLASK, "flask is not installed")
class TestFlaskAdapter(unittest.TestCase, _AdapterCases):
    def setUp(self) -> None:
        self.kernel = _kernel()
        self.client = create_flask_app(self.kernel).test_client()

    def post(self, payload: dict) -> dict:
        response = self.client.post("/submit", json=payload)
        self.assertEqual(response.status_code, 200)
        return response.get_json()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is not installed")
class TestFastAPIAdapter(unittest.TestCase, _AdapterCases):
    def setUp(self) -> None:
        self.kernel = _kernel()
        self.client = TestClient(create_fastapi_app(self.kernel))

    def post(self, payload: dict) -> dict:
        response = self.client.post("/submit", json=payload)
        self.assertEqual(response.status_code, 200)
        return response.json()


class TestSdkServer(unittest.TestCase, _AdapterCases):
    def setUp(self) -> None:
        self.kernel = _kernel()
        self.server = KernelServer(self.kernel, host="127.0.0.1", port=0)
        # Bind an ephemeral port, then start.
        from http.server import HTTPServer

        handler = self.server._create_handler()
        self.server._server = HTTPServer(("127.0.0.1", 0), handler)
        self.server.port = self.server._server.server_address[1]
        import threading

        self._thread = threading.Thread(target=self.server._server.serve_forever)
        self._thread.daemon = True
        self._thread.start()

    def tearDown(self) -> None:
        self.server.stop()

    def post(self, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.server.port}/submit",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_client_round_trip(self) -> None:
        params = {"text": "via-client"}
        permit = _permit("echo", params)
        client = KernelClient(f"http://127.0.0.1:{self.server.port}")
        receipt = client.submit(
            KernelRequest(
                request_id="client",
                ts_ms=1000,
                actor="alice",
                intent="Echo through the client",
                tool_call=ToolCall(name="echo", params=dict(params)),
                params=dict(params),
            ),
            permit_token=permit,  # type: ignore[arg-type]
        )
        self.assertEqual(receipt.decision, Decision.ALLOW)
        self.assertEqual(receipt.tool_result, "via-client")
        denied = client.submit(
            KernelRequest(
                request_id="client-denied",
                ts_ms=1000,
                actor="alice",
                intent="Echo without a permit",
                tool_call=ToolCall(name="echo", params={"text": "no"}),
                params={"text": "no"},
            )
        )
        self.assertEqual(denied.decision, Decision.DENY)
        self.assertIn("MISSING_PERMIT", denied.error or "")


class TestMCPAdapter(unittest.TestCase):
    def test_permit_allows_and_mismatch_denies(self) -> None:
        kernel = _kernel()
        adapter = MCPAdapter(kernel, actor="alice")

        def echo(text: str) -> str:
            return text

        adapter.register_tool("echo", echo, "echo text")
        allowed = adapter.handle_tool_call(
            MCPToolCall(id="1", name="echo", arguments={"text": "hi"}),
            permit_token=_permit("echo", {"text": "hi"}),  # type: ignore[arg-type]
        )
        self.assertFalse(allowed.is_error)
        self.assertEqual(allowed.content, "hi")

        missing = adapter.handle_tool_call(
            MCPToolCall(id="2", name="echo", arguments={"text": "hi"})
        )
        self.assertTrue(missing.is_error)
        self.assertIn("MISSING_PERMIT", missing.content["error"])

        mismatched = adapter.handle_tool_call(
            MCPToolCall(id="3", name="echo", arguments={"text": "no"}),
            permit_token=_permit("echo", {"text": "hi"}),  # type: ignore[arg-type]
        )
        self.assertTrue(mismatched.is_error)


class TestHaltSurvivesReset(unittest.TestCase):
    def test_state_machine_reset_does_not_resume_a_halted_kernel(self) -> None:
        kernel = _kernel()
        called: list[str] = []
        kernel._dispatcher.registry.register(
            "spy", lambda text: called.append(text) or text
        )
        kernel.halt("stop")
        machine = kernel._state_machine
        assert machine is not None
        machine.reset(KernelState.IDLE)
        self.assertEqual(machine.state, KernelState.IDLE)
        params = {"text": "hi"}
        with self.assertRaises(StateError):
            kernel.submit(
                KernelRequest(
                    request_id="after-reset",
                    ts_ms=1000,
                    actor="alice",
                    intent="Must not run",
                    tool_call=ToolCall(name="spy", params=params),
                    params=params,
                ),
                permit_token=_permit("spy", params),  # type: ignore[arg-type]
            )
        self.assertEqual(called, [])

    def test_bare_state_machine_reset_is_not_a_kernel(self) -> None:
        machine = StateMachine()
        machine.transition(KernelState.IDLE)
        machine.halt()
        machine.reset(KernelState.IDLE)
        self.assertEqual(machine.state, KernelState.IDLE)


class TestAsyncKernelGovernance(unittest.TestCase):
    def _request(self, request_id: str, params: dict) -> KernelRequest:
        return KernelRequest(
            request_id=request_id,
            ts_ms=1000,
            actor="alice",
            intent="Echo hi",
            tool_call=ToolCall(name="spy", params=dict(params)),
            params=dict(params),
        )

    def test_async_wrapper_keeps_the_sync_guarantees(self) -> None:
        import asyncio

        from kernels.async_support.async_kernel import AsyncStrictKernel

        async def scenario() -> None:
            kernel = AsyncStrictKernel("async-k")
            kernel.set_keyring(KEYRING)
            called: list[str] = []
            kernel.kernel._dispatcher.registry.register(  # type: ignore[union-attr]
                "spy", lambda text: called.append(text) or text
            )
            params = {"text": "hi"}
            denied = await kernel.submit(self._request("a1", params))
            self.assertEqual(denied.decision, Decision.DENY)
            self.assertIn("MISSING_PERMIT", denied.error or "")
            self.assertEqual(called, [])

            permit = _permit("spy", params)
            mismatched = await kernel.submit(
                self._request("a2", {"text": "other"}),
                permit_token=permit,  # type: ignore[arg-type]
            )
            self.assertIn("PARAM", mismatched.error or "")
            self.assertEqual(called, [])

            allowed = await kernel.submit(
                self._request("a3", params),
                permit_token=permit,  # type: ignore[arg-type]
            )
            self.assertEqual(allowed.tool_result, "hi")
            self.assertEqual(called, ["hi"])
            phases = [
                entry.audit_phase
                for entry in kernel.export_evidence().ledger_entries
                if entry.request_id == "a3"
            ]
            self.assertEqual(phases, ["intent", "outcome"])

            replay = await kernel.submit(
                self._request("a4", params),
                permit_token=permit,  # type: ignore[arg-type]
            )
            self.assertIn("REPLAY_DETECTED", replay.error or "")
            self.assertEqual(called, ["hi"])

            import kernels.variants.base as base

            original = base.validate_request

            def explode(_request: KernelRequest) -> list[str]:
                raise RuntimeError("validator exploded")

            base.validate_request = explode  # type: ignore[assignment]
            try:
                with self.assertRaises(RuntimeError):
                    await kernel.submit(
                        KernelRequest(
                            request_id="a5",
                            ts_ms=1000,
                            actor="alice",
                            intent="Fault the kernel",
                        )
                    )
            finally:
                base.validate_request = original  # type: ignore[assignment]
            self.assertEqual(kernel.state, KernelState.HALTED)

        asyncio.run(scenario())


class TestAsyncDispatcherDoesNotRunTools(unittest.TestCase):
    def test_dispatch_does_not_call_the_handler(self) -> None:
        import asyncio

        from kernels.async_support.async_dispatcher import (
            AsyncDispatcher,
            AsyncToolRegistry,
        )

        called: list[str] = []

        async def scenario() -> None:
            registry = AsyncToolRegistry()
            registry.register_tool("spy", lambda text: called.append(text) or text)
            result = await AsyncDispatcher(registry).dispatch(
                ToolCall(name="spy", params={"text": "hi"})
            )
            self.assertFalse(result.success)
            self.assertIn("MISSING_PERMIT", result.error or "")
            self.assertEqual(called, [])

        asyncio.run(scenario())


class TestClientRejectsBrokenServer(unittest.TestCase):
    def test_http_error_is_a_kernel_error(self) -> None:
        from kernels.common.errors import KernelError

        client = KernelClient("http://127.0.0.1:1")
        with self.assertRaises(KernelError):
            client.health()
