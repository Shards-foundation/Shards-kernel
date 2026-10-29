"""CrewAI adapter tests without requiring the CrewAI runtime."""

import asyncio

import pytest

from kernels.integrations.crewai_adapter import CrewAIAdapter, GovernedCrewAITool
from kernels.integrations.wire import boot_strict_kernel


def test_crewai_adapter_tool_registry_and_delegation_matrix():
    kernel = boot_strict_kernel("crewai-test")
    adapter = CrewAIAdapter(kernel, actor="orchestrator", auto_register=False)
    tool = adapter.wrap_tool("lookup", lambda key: key, description="lookup")
    assert isinstance(tool, GovernedCrewAITool)
    assert adapter.get_tool("lookup") is tool
    assert adapter.get_tool("missing") is None
    assert adapter.list_tools() == ["lookup"]
    assert adapter.create_agent_identity("Senior Researcher", "a1") == "senior-researcher-a1"
    generated = adapter.create_agent_identity("Writer")
    assert generated.startswith("writer-")
    assert adapter.validate_delegation("manager", "writer", "draft") is True
    matrix = {"manager": ["researcher"], "researcher": []}
    assert adapter.validate_delegation("manager", "researcher", "research", matrix)
    assert not adapter.validate_delegation("manager", "writer", "draft", matrix)
    assert not adapter.validate_delegation("unknown", "writer", "draft", matrix)
    assert adapter.export_evidence()["kernel_id"] == "crewai-test"


def test_crewai_sync_and_async_tool_paths_fail_closed_without_permit():
    kernel = boot_strict_kernel("crewai-deny-test")
    tool = CrewAIAdapter(kernel, auto_register=False).wrap_tool(
        "lookup", lambda key: key
    )
    with pytest.raises(PermissionError, match="denied by KERNELS"):
        tool._run(key="secret")
    with pytest.raises(PermissionError, match="denied by KERNELS"):
        asyncio.run(tool._arun(key="secret"))
