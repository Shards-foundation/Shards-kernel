"""Allowed-path tests for adapters using a deterministic fake kernel."""

from types import SimpleNamespace

from shards_kernel.common.types import (
    Decision,
    EvidenceBundle,
    KernelReceipt,
    KernelState,
    ReceiptStatus,
    VirtualClock,
)
from shards_kernel.integrations.autogpt_adapter import AutoGPTAdapter
from shards_kernel.integrations.crewai_adapter import CrewAIAdapter
from shards_kernel.integrations.generic_adapter import GenericAdapter
from shards_kernel.integrations.huggingface_adapter import HuggingFaceAdapter
from shards_kernel.integrations.langchain_adapter import LangChainAdapter
from shards_kernel.integrations.langgraph_adapter import LangGraphAdapter
from shards_kernel.integrations.mcp_adapter import MCPAdapter, MCPToolCall


class Registry:
    def __init__(self):
        self.items = {}

    def register(self, name, handler, description=""):
        self.items[name] = handler

    def has(self, name):
        return name in self.items

    def get(self, name):
        return self.items.get(name)


class FakeKernel:
    def __init__(self):
        self.config = SimpleNamespace(
            kernel_id="fake",
            variant="strict",
            clock=VirtualClock(0),
        )
        self._dispatcher = SimpleNamespace(registry=Registry())
        self.policy = SimpleNamespace(
            allowed_actors=frozenset({"agent"}),
            allowed_tools=frozenset({"echo"}),
            allow_intent_only=False,
            max_intent_length=1000,
        )
        self.halted = False
        self.requests = []

    def submit(self, request, permit_token=None):
        self.requests.append((request, permit_token))
        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.ACCEPTED,
            state_from=KernelState.IDLE,
            state_to=KernelState.COMPLETED,
            ts_ms=0,
            decision=Decision.ALLOW,
            tool_result=request.params,
        )

    def export_evidence(self):
        return EvidenceBundle((), "root", 0, "fake", "strict")

    def halt(self, reason="halt"):
        self.halted = True
        return KernelReceipt(
            request_id="halt",
            status=ReceiptStatus.ACCEPTED,
            state_from=KernelState.IDLE,
            state_to=KernelState.HALTED,
            ts_ms=0,
            decision=Decision.HALT,
        )

    def get_state(self):
        return KernelState.HALTED if self.halted else KernelState.IDLE


def test_generic_adapter_allowed_wrapper_and_factory():
    kernel = FakeKernel()
    adapter = GenericAdapter(kernel, auto_register=False)
    result = adapter.call_tool("echo", {"message": "ok"})
    assert result.was_allowed is True
    assert result.result == {"message": "ok"}
    assert result.audit_hash is None
    wrapped = adapter.create_wrapper("echo", lambda **kwargs: "ignored")
    assert wrapped(message="next") == {"message": "next"}
    assert adapter.export_evidence()["entry_count"] == 0
    adapter.halt()
    assert kernel.halted is True


def test_autogpt_adapter_allowed_command_records_monitor_stats():
    kernel = FakeKernel()
    adapter = AutoGPTAdapter(kernel, auto_register=False)
    command = adapter.wrap_command("echo", lambda message: message, risk_score=0.8)
    assert command(message="ok") == "{'message': 'ok'}"
    assert adapter.monitor.stats.commands_executed == 1
    assert adapter.monitor.stats.high_risk_actions == 1
    assert adapter.get_command("echo") is command
    assert adapter.export_evidence()["kernel_id"] == "fake"


def test_huggingface_allowed_call_and_forward():
    kernel = FakeKernel()
    adapter = HuggingFaceAdapter(kernel)
    tool = adapter.wrap_tool("echo", lambda message: message)
    assert tool(message="ok") == {"message": "ok"}
    assert tool.forward(message="next") == {"message": "next"}
    assert adapter.export_evidence()["entry_count"] == 0


def test_langchain_allowed_run_invoke_and_direct_call():
    kernel = FakeKernel()
    adapter = LangChainAdapter(kernel)
    tool = adapter.wrap_tool("echo", lambda message: message)
    assert tool.run(message="ok").was_allowed is True
    assert tool.invoke("hello") == {"input": "hello"}
    assert tool(message="direct") == {"message": "direct"}
    assert adapter.export_evidence()["entry_count"] == 0


def test_crewai_allowed_sync_and_async_run():
    kernel = FakeKernel()
    tool = CrewAIAdapter(kernel, auto_register=False).wrap_tool(
        "echo", lambda message: message
    )
    assert tool._run(message="ok") == "{'message': 'ok'}"

    import asyncio
    assert asyncio.run(tool._arun(message="async")) == "{'message': 'async'}"


def test_langgraph_allowed_node_tracks_transition_and_invariants():
    kernel = FakeKernel()
    adapter = LangGraphAdapter(kernel, auto_register=False)
    adapter.add_invariant("nonempty", "state has data", lambda state: bool(state))
    node = adapter.wrap_node("process", lambda state: {**state, "done": True})
    assert node({"value": 1}) == {"value": 1}
    transition = adapter.get_transitions()[0]
    assert transition.was_allowed is True
    assert transition.to_node == "process"
    assert adapter.export_evidence()["workflow_data"]["transitions"][0]["was_allowed"]
    adapter.reset_workflow()
    assert adapter.get_transitions() == []


def test_mcp_allowed_call_and_server_halt():
    kernel = FakeKernel()
    adapter = MCPAdapter(kernel)
    result = adapter.handle_tool_call(MCPToolCall("c1", "echo", {"message": "ok"}))
    assert result.is_error is False
    assert result.content == {"message": "ok"}
    assert adapter.export_evidence()["entry_count"] == 0
    adapter.halt()
    assert kernel.halted is True
