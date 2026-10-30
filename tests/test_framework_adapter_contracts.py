"""Framework adapter contracts and fail-closed behaviour."""

import pytest

from shards_kernel.common.errors import PermitError
from shards_kernel.integrations.autogpt_adapter import AutoGPTAdapter, AutonomousLoopMonitor
from shards_kernel.integrations.generic_adapter import GenericAdapter
from shards_kernel.integrations.huggingface_adapter import HuggingFaceAdapter, PermitInjector
from shards_kernel.integrations.langchain_adapter import LangChainAdapter
from shards_kernel.integrations.langgraph_adapter import LangGraphAdapter
from shards_kernel.integrations.mcp_adapter import MCPAdapter, MCPToolCall
from shards_kernel.integrations.wire import boot_strict_kernel


def test_generic_adapter_registry_wrappers_and_evidence():
    kernel = boot_strict_kernel("generic-test")
    adapter = GenericAdapter(kernel, auto_register=False)
    adapter.register_tool("echo", lambda value: value)
    assert "echo" in adapter._tools
    wrapped = adapter.create_wrapper("echo", lambda value: value, raise_on_deny=False)
    assert wrapped(value="x") is None
    with pytest.raises(PermitError):
        adapter.create_wrapper("echo2", lambda: "x")( )
    assert adapter.export_evidence()["kernel_id"] == "generic-test"
    adapter.halt()


def test_autogpt_monitor_limits_risk_and_reset():
    monitor = AutonomousLoopMonitor(max_iterations=1, max_denials=2)
    assert monitor.should_halt() is False
    monitor.record_iteration()
    monitor.record_command(allowed=False, risk_score=0.9)
    assert monitor.stats.commands_denied == 1
    assert monitor.stats.high_risk_actions == 1
    assert monitor.should_halt() is True
    assert monitor.get_halt_reason() == "Maximum iterations reached"
    monitor.reset()
    assert monitor.should_halt() is False
    monitor.record_command(allowed=True, risk_score=0.1)
    assert monitor.stats.commands_executed == 1


def test_autogpt_adapter_risk_validation_and_denied_command():
    kernel = boot_strict_kernel("autogpt-test")
    adapter = AutoGPTAdapter(kernel, auto_register=False)
    assert adapter.get_risk_score("unknown") == 0.5
    adapter.set_risk_score("read_file", 0.1)
    assert adapter.get_risk_score("read_file") == 0.1
    with pytest.raises(ValueError):
        adapter.set_risk_score("bad", 1.1)
    command = adapter.wrap_command("read_file", lambda path: path, risk_score=0.2)
    assert adapter.get_command("read_file") is command
    assert "read_file" in adapter.list_commands()
    with pytest.raises(PermissionError):
        command(path="secret.txt")
    assert adapter.monitor.stats.commands_denied == 1
    assert adapter.export_evidence()["kernel_id"] == "autogpt-test"
    adapter.reset_monitor()
    adapter.halt("test stop")


def test_autogpt_monitor_runtime_and_denial_limits(monkeypatch):
    monitor = AutonomousLoopMonitor(max_runtime_seconds=0, max_denials=1)
    assert monitor.should_halt() is True
    assert monitor.get_halt_reason() == "Maximum runtime exceeded"
    monitor.reset()
    monitor.max_runtime_seconds = None
    monitor.record_command(allowed=False, risk_score=0)
    assert monitor.should_halt() is True
    assert monitor.get_halt_reason() == "Maximum denials reached"


def test_huggingface_adapter_wrapping_and_permit_injector():
    kernel = boot_strict_kernel("hf-test")
    adapter = HuggingFaceAdapter(kernel)
    tool = adapter.wrap_tool("hf_echo", lambda value: value, inputs={"value": "string"})
    assert adapter.get_tool("hf_echo") is tool
    assert adapter.list_tools() == ["hf_echo"]
    assert tool.inputs_schema == {"value": "string"}
    assert tool.outputs == "any"
    with pytest.raises(PermitError):
        tool.forward(value="blocked")
    injector = PermitInjector(adapter)
    assert injector.get_permit("hf_echo") is None
    injector.set_permit("hf_echo", object())
    assert injector.get_permit("hf_echo") is not None
    injector.clear_permit("hf_echo")
    injector.clear_permit("missing")
    injector.set_permit("one", object())
    injector.set_permit("two", object())
    injector.clear_all_permits()
    assert injector.get_permit("one") is None
    assert adapter.export_evidence()["kernel_id"] == "hf-test"
    adapter.halt()


def test_langchain_adapter_wrapping_invocation_and_permit_state():
    kernel = boot_strict_kernel("langchain-test")
    adapter = LangChainAdapter(kernel)
    tool = adapter.wrap_tool("lookup", lambda key: key)
    assert adapter.get_tool("lookup") is tool
    assert adapter.list_tools() == ["lookup"]
    result = tool.run(key="value")
    assert result.was_allowed is False
    with pytest.raises(PermitError):
        tool.invoke("value")
    with pytest.raises(PermitError):
        tool(key="value")
    adapter.set_permit(None)
    adapter.clear_permit()
    assert adapter.export_evidence()["kernel_id"] == "langchain-test"
    adapter.halt()


def test_langgraph_invariants_node_registry_and_denial_path():
    kernel = boot_strict_kernel("langgraph-test")
    adapter = LangGraphAdapter(kernel, auto_register=False)
    adapter.add_invariant("budget", "cost must fit", lambda state: state.get("cost", 0) <= 5)
    assert adapter.check_invariants({"cost": 4}) == []
    with pytest.raises(RuntimeError, match="Workflow invariant violated"):
        adapter.check_invariants({"cost": 6})
    adapter.add_invariant("soft", "soft rule", lambda _state: False, enforce=False)
    assert adapter.check_invariants({"cost": 4}) == ["soft"]
    node = adapter.wrap_node("process", lambda state: {**state, "done": True})
    assert adapter.get_node("process") is node
    assert adapter.list_nodes() == ["process"]
    with pytest.raises(PermissionError):
        node({"cost": 2})
    assert len(adapter.get_transitions()) == 1
    assert adapter.get_transitions()[0].was_allowed is False
    assert adapter.export_evidence()["workflow_data"]["nodes"] == ["process"]
    adapter.reset_workflow()
    assert adapter.get_transitions() == []


def test_mcp_adapter_registers_lists_and_denies_without_permit():
    kernel = boot_strict_kernel("mcp-test")
    adapter = MCPAdapter(kernel)
    adapter.register_tool("echo", lambda value: value, description="echo")
    assert adapter.list_tools()[0]["name"] == "echo"
    result = adapter.handle_tool_call(MCPToolCall("call-1", "echo", {"value": "x"}))
    assert result.call_id == "call-1"
    assert result.is_error is True
    json_result = adapter.handle_tool_call_json(
        {"id": "call-2", "name": "echo", "arguments": {"value": "y"}}
    )
    assert json_result["is_error"] is True
    assert adapter.export_evidence()["kernel_id"] == "mcp-test"
    adapter.halt()
