"""Headless interaction and safety tests for the optional full-screen TUI."""

import asyncio
import json

import pytest

pytest.importorskip("textual")

from shards_kernel.cli.tui import MissionControlApp


def test_keyboard_navigation_and_real_diagnostics():
    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(45, 30)) as pilot:
            assert app.last_action == "welcome"
            await pilot.press("1")
            assert app.last_action == "info"
            await pilot.press("2")
            assert app.last_action == "diagnostics"
            assert app.last_report is not None
            assert app.last_report["library"]["profile"] == "library"
            assert app.last_report["service"]["profile"] == "service"
            assert app.last_report["service"]["scope"].startswith("Preflight environment")
            from textual.widgets import Footer
            assert app.query_one(Footer) is not None
            await pilot.press("4")
            assert app.last_action == "reference"
            await pilot.press("r")
            assert app.last_action == "refresh"

    asyncio.run(scenario())


def test_touch_target_dispatches_offline_demo():
    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(46, 34)) as pilot:
            await pilot.click("#demo")
            assert app.last_action == "demo"
            assert app.last_report is not None
            result = app.last_report["demo"]
            assert result["demo"] == "OFFLINE_ONLY"
            assert result["production_ready"] is False
            assert result["passed"] is True

    asyncio.run(scenario())


def test_diagnostic_error_does_not_leak_exception_text(monkeypatch):
    from shards_kernel.cli import doctor

    def failing_diagnostic(profile):
        raise RuntimeError("secret-should-not-appear " + profile)

    monkeypatch.setattr(doctor, "diagnose", failing_diagnostic)
    app = MissionControlApp(pulse_enabled=False)
    lines = []
    monkeypatch.setattr(app, "_log", lambda *items: lines.extend(items))
    app.action_diagnostics()
    assert app.last_report is None
    assert "RuntimeError" in str(lines)
    assert "secret-should-not-appear" not in str(lines)


def test_preflight_does_not_echo_credentials(monkeypatch):
    from shards_kernel.cli.doctor import diagnose

    value = "do-not-print-this-example-value-123456789"
    monkeypatch.setenv("SHARDS_KERNEL_API_KEY", value)
    output = json.dumps(diagnose(profile="service"))
    assert value not in output


def test_failed_demo_clears_previous_report(monkeypatch):
    from shards_kernel.cli import demo

    def failing_demo():
        raise RuntimeError("do-not-leak-this-secret")

    monkeypatch.setattr(demo, "run_scenario", failing_demo)
    app = MissionControlApp(pulse_enabled=False)
    app.last_report = {"library": {"ready": True}}
    lines = []
    monkeypatch.setattr(app, "_log", lambda *items: lines.extend(items))
    app.action_demo()
    assert app.last_action == "demo"
    assert app.last_report is None
    assert "RuntimeError" in str(lines)
    assert "do-not-leak-this-secret" not in str(lines)


def test_long_tokens_wrap_for_small_termux_screen():
    token = "shards-kernel-" * 12
    parts = MissionControlApp._wrap_line(token, 24)
    assert len(parts) > 1
    assert all(len(part) <= 24 for part in parts)
    assert "".join(parts) == token


def test_native_footer_and_command_palette_on_mobile():
    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(42, 30)) as pilot:
            from textual.widgets import Footer
            assert app.query_one(Footer) is not None
            await pilot.press("2")
            assert app.last_action == "diagnostics"
            await pilot.press("ctrl+p")
            assert app.screen.__class__.__name__ == "CommandPalette"
    asyncio.run(scenario())


def test_theme_picker_can_open_directly():
    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(42, 30)) as pilot:
            await pilot.press("t")
            assert app.screen.__class__.__name__ == "CommandPalette"
    asyncio.run(scenario())


def test_narrow_terminal_touch_buttons_and_preflight_matrix():
    """Touch targets must work at 42 columns; the matrix must show actual preflight."""
    from textual.widgets import Static

    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(42, 30)) as pilot:
            matrix = app.query_one("#matrix", Static)
            assert all(len(line) <= 36 for line in app._matrix_content().splitlines())
            assert "SERVICE  NOT INSPECTED" in str(matrix.content)
            await pilot.click("#info")
            assert app.last_action == "info"
            await pilot.click("#diagnostics")
            assert app.last_action == "diagnostics"
            assert app.last_report is not None
            expected = str(app.last_report["service"]["assessment"]) + " (PREFLIGHT)"
            assert ("SERVICE  " + expected) in str(matrix.content)

    asyncio.run(scenario())


def test_mounted_preflight_failure_restores_status_panel(monkeypatch):
    """A failed refresh must not display an earlier successful service result."""
    from shards_kernel.cli import doctor
    from textual.widgets import Static

    original = doctor.diagnose

    async def scenario():
        app = MissionControlApp(pulse_enabled=False)
        async with app.run_test(size=(42, 30)) as pilot:
            await pilot.click("#diagnostics")
            assert app.last_report is not None
            matrix = app.query_one("#matrix", Static)
            assert "PREFLIGHT" in str(matrix.content)

            def reject_service(profile):
                if profile == "service":
                    raise RuntimeError("sensitive-failure-detail")
                return original(profile=profile)

            monkeypatch.setattr(doctor, "diagnose", reject_service)
            # Exercise the error-reset path directly; the separate touch test
            # verifies click dispatch, and repeated clicks can be coalesced.
            app.action_diagnostics()
            assert app.last_report is None
            assert "SERVICE  NOT INSPECTED" in str(matrix.content)
            assert "sensitive-failure-detail" not in str(matrix.content)

    asyncio.run(scenario())
