"""Tool registry boundary and failure-path tests."""

import pytest

from shards_kernel.common.errors import ToolError
from shards_kernel.execution.tools import ToolRegistry, create_default_registry


def test_registry_lookup_registration_and_removal():
    registry = ToolRegistry()
    assert registry.get("missing") is None
    assert registry.has("missing") is False
    registry.register("echo", lambda value: value, param_schema={"value": str})
    assert registry.has("echo") is True
    assert registry.get("echo").description == ""
    assert registry.list_tools() == ["echo"]
    with pytest.raises(ToolError, match="already registered"):
        registry.register("echo", lambda: None)
    registry.unregister("echo")
    assert registry.has("echo") is False
    with pytest.raises(ToolError, match="is not registered"):
        registry.unregister("echo")


def test_registry_invocation_errors_are_wrapped():
    registry = ToolRegistry()
    registry.register("echo", lambda value: value)
    with pytest.raises(ToolError, match="not found"):
        registry.invoke("missing", {})
    with pytest.raises(ToolError, match="Invalid parameters"):
        registry.invoke("echo", {})
    registry.register("explode", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(ToolError, match="execution failed"):
        registry.invoke("explode", {})


def test_default_registry_tools_and_results():
    registry = create_default_registry()
    assert registry.invoke("echo", {"text": "hello"}) == "hello"
    assert registry.invoke("add", {"a": 2, "b": 3}) == 5
    assert registry.list_tools() == ["echo", "add"]
