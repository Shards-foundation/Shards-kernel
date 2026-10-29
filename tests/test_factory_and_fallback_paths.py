"""Factory, compatibility and server fallback-path tests."""

import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from types import SimpleNamespace

import pytest

from kernels.integrations.autogpt_adapter import create_autogpt_adapter
from kernels.integrations.generic_adapter import (
    MoltbookAdapter,
    create_generic_adapter,
    create_moltbook_adapter,
)
from kernels.integrations.huggingface_adapter import create_huggingface_adapter
from kernels.integrations.langchain_adapter import create_langchain_adapter
from kernels.integrations.mcp_adapter import MCPServer, create_mcp_adapter
from kernels.integrations.wire import boot_strict_kernel
from kernels.sdk.server import KernelRequestHandler, KernelServer, run_server


@pytest.mark.parametrize("variant", ["strict", "permissive", "evidence-first"])
def test_generic_adapter_factory_variants(variant):
    adapter = create_generic_adapter(kernel_id="factory-test", variant=variant)
    assert adapter.kernel.config.variant == variant
    assert adapter.actor == "generic-agent"


def test_generic_and_moltbook_factories_reject_unknown_variant():
    with pytest.raises(ValueError, match="Unknown variant"):
        create_generic_adapter(variant="unknown")
    adapter = create_moltbook_adapter(kernel_id="moltbook-test")
    assert isinstance(adapter, MoltbookAdapter)
    assert adapter.kernel.config.kernel_id == "moltbook-test"


def test_moltbook_adapter_callable_execute_and_invalid_tool_paths():
    adapter = MoltbookAdapter(boot_strict_kernel("moltbook-wrapper"), auto_register=False)
    callable_wrapper = adapter.wrap_moltbook_tool(lambda value: value, name="callable")
    assert callable(callable_wrapper)

    class ExecuteTool:
        name = "execute-tool"
        description = "Execute a test operation"

        def execute(self, value):
            return value

    execute_wrapper = adapter.wrap_moltbook_tool(ExecuteTool())
    assert callable(execute_wrapper)

    with pytest.raises(ValueError, match="is not callable"):
        adapter.wrap_moltbook_tool(object(), name="invalid")


@pytest.mark.parametrize("variant", ["strict", "permissive", "evidence-first"])
def test_huggingface_factory_variants(variant):
    adapter = create_huggingface_adapter(kernel_id="hf-factory", variant=variant)
    assert adapter.kernel.config.variant == variant


def test_huggingface_factory_rejects_unknown_variant_and_wraps_existing_tools():
    with pytest.raises(ValueError, match="Unknown variant"):
        create_huggingface_adapter(variant="unknown")
    adapter = create_huggingface_adapter(kernel_id="hf-wrap-test")

    existing = SimpleNamespace(
        name="existing-hf-tool",
        description="existing",
        inputs={"value": "string"},
        output_type="string",
        forward=lambda value: value,
    )
    wrapped = adapter.wrap_hf_tool(existing)
    assert wrapped.name == "existing-hf-tool"
    assert wrapped.inputs_schema == {"value": "string"}

    plain = adapter.wrap_hf_tool(lambda value: value)
    assert plain.name == "unknown_tool"
    multi = create_huggingface_adapter(kernel_id="hf-multi")
    tools = multi.wrap_tools([
        SimpleNamespace(name="one", forward=lambda: 1),
        SimpleNamespace(name="two", forward=lambda: 2),
    ])
    assert [tool.name for tool in tools] == ["one", "two"]


@pytest.mark.parametrize("variant", ["strict", "permissive", "evidence-first"])
def test_langchain_factory_variants(variant):
    adapter = create_langchain_adapter(kernel_id="lc-factory", variant=variant)
    assert adapter.kernel.config.variant == variant


def test_langchain_factory_rejects_unknown_variant():
    with pytest.raises(ValueError, match="Unknown variant"):
        create_langchain_adapter(variant="unknown")


def test_autogpt_factory_monitor_disabled_and_kill_switch():
    kernel = boot_strict_kernel("autogpt-factory")
    adapter = create_autogpt_adapter(kernel, enable_monitoring=False, auto_register=False)
    assert adapter.monitor is None
    adapter.reset_monitor()
    adapter.halt("ignored without monitor")

    halted = create_autogpt_adapter(
        boot_strict_kernel("autogpt-kill"),
        auto_register=False,
        max_autonomous_iterations=0,
    )
    command = halted.wrap_command("do_work", lambda: "done")
    with pytest.raises(RuntimeError, match="Autonomous loop halted"):
        command()


def test_mcp_factory_and_server_keyboard_interrupt(monkeypatch, capsys):
    adapter = create_mcp_adapter(kernel_id="mcp-factory")
    assert adapter.kernel.config.kernel_id == "mcp-factory"

    server = MCPServer(boot_strict_kernel("mcp-interrupt"))
    monkeypatch.setattr("sys.stdin", SimpleNamespace(readline=lambda: (_ for _ in ()).throw(KeyboardInterrupt)))
    server.run()
    assert capsys.readouterr().out == ""


def test_sdk_server_no_kernel_routes_and_options():
    class NoKernelHandler(KernelRequestHandler):
        kernel = None

    httpd = HTTPServer(("127.0.0.1", 0), NoKernelHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        for path in ("/health", "/status", "/evidence", "/policy"):
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + path, timeout=2)
            assert error.value.code == 503
        for path, payload in (("/submit", {"request_id": "x"}), ("/halt", {})):
            request = urllib.request.Request(
                base + path,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(Exception) as error:
                urllib.request.urlopen(request, timeout=2)
            assert getattr(error.value, "code", None) == 503
        options = urllib.request.Request(base + "/anything", method="OPTIONS")
        with urllib.request.urlopen(options, timeout=2) as response:
            assert response.status == 200
            assert response.headers["Access-Control-Allow-Methods"] == "GET, POST, OPTIONS"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_run_server_stops_after_keyboard_interrupt(monkeypatch, capsys):
    stopped = []

    def interrupt(self, blocking=True):
        raise KeyboardInterrupt

    monkeypatch.setattr(KernelServer, "start", interrupt)
    monkeypatch.setattr(KernelServer, "stop", lambda self: stopped.append(True))
    run_server(kernel_id="interrupt-test", port=0)
    assert stopped == [True]
    assert "Shutting down" in capsys.readouterr().out
