"""Regression tests for optional, read-only mission-control UI."""

import builtins
import sys

from shards_kernel import __main__ as cli
from shards_kernel.cli import mission_control


def test_dashboard_plain_noninteractive(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["shards-kernel", "dashboard", "--plain", "--no-interactive"]
    )
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "SHARDS // KERNEL" in output
    assert "NOT VERIFIED" in output
    assert "no service inspected" in output
    assert "shards-kernel doctor --profile service" in output
    assert "\x1b[" not in output


def test_dashboard_no_prompt_when_noninteractive(monkeypatch, capsys):
    def forbidden_input(_prompt):
        raise AssertionError("Non-interactive mode must never read stdin")
    monkeypatch.setattr(builtins, "input", forbidden_input)
    assert mission_control.run_dashboard(plain=True, interactive=False) is None
    assert "[Q] Exit" in capsys.readouterr().out


def test_input_selection_only_returns_safe_action(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda _prompt: "2")
    assert mission_control.run_dashboard(plain=True, interactive=True) == "doctor"
    assert "NOT VERIFIED" in capsys.readouterr().out


def test_unknown_selection_does_nothing(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda _prompt: "launch")
    assert mission_control.run_dashboard(plain=True, interactive=True) is None
    capsys.readouterr()


def test_keyboard_interrupt_exits_gracefully(monkeypatch, capsys):
    def interrupt(_prompt):
        raise KeyboardInterrupt
    monkeypatch.setattr(builtins, "input", interrupt)
    assert mission_control.run_dashboard(plain=True, interactive=True) is None
    assert "SHARDS // KERNEL" in capsys.readouterr().out


def test_no_colour_environment_uses_plain_renderer(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(mission_control.sys.stdout, "isatty", lambda: True)
    assert mission_control.run_dashboard(interactive=False) is None
    assert "SHARDS // KERNEL" in capsys.readouterr().out


def test_version_output_has_no_banner(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["shards-kernel", "--version"])
    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == 0
    output = capsys.readouterr().out
    assert output.startswith("shards-kernel ")
    assert "SHARDS // KERNEL" not in output


def test_standalone_renderer_path(capsys):
    """Running the downloaded module as a script must render, not silently exit."""
    import runpy

    runpy.run_path(mission_control.__file__, run_name="__main__")
    output = capsys.readouterr().out
    assert "SHARDS // KERNEL" in output


def test_padded_choice_matches_displayed_menu(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda _prompt: "02")
    assert mission_control.run_dashboard(plain=True, interactive=True) == "doctor"
    capsys.readouterr()


def test_rich_welcome_renders_without_claiming_live_service(capsys):
    """Exercise the optional Rich fallback used when Textual is unavailable."""
    mission_control._rich_dashboard(animate=False)
    output = capsys.readouterr().out
    assert "SHARDS" in output
    assert "MISSION COMMANDS" in output
    assert "SERVICE" in output
    assert "NOT INSPECTED" in output
    assert "NOT VERIFIED" in output


def test_dashboard_fallback_preflight_checks_service_not_just_library(monkeypatch):
    """Interactive fallback must not report a ready service from library-only checks."""
    from argparse import ArgumentParser
    from shards_kernel.cli import doctor

    observed = []

    monkeypatch.setattr(
        mission_control, "run_dashboard", lambda **kwargs: "doctor"
    )

    def fake_doctor(*, profile, json_output):
        observed.append((profile, json_output))
        return 2

    monkeypatch.setattr(doctor, "run_doctor", fake_doctor)
    result = cli._cmd_dashboard(ArgumentParser(), plain=True, interactive=True)
    assert result == 2
    assert observed == [("service", False)]



def test_plain_mode_shows_optional_colour_install_hint(capsys):
    mission_control._plain_dashboard(rich_missing=True)
    output = capsys.readouterr().out
    assert "shards-kernel[tui]" in output
    assert "NOT VERIFIED" in output


def test_rich_renderer_wide_and_narrow_with_animation(monkeypatch, capsys):
    """Exercise both layout paths and the animated status without real delays."""
    import rich.console

    real_console = rich.console.Console
    monkeypatch.setattr(mission_control.time, "sleep", lambda seconds: None)
    for width in (120, 42):
        monkeypatch.setattr(
            rich.console,
            "Console",
            lambda _width=width, **kwargs: real_console(width=_width, **kwargs),
        )
        mission_control._rich_dashboard(animate=width == 42)
    output = capsys.readouterr().out
    assert output.count("SHARDS") >= 2
    assert "CONTROL MATRIX" in output
    assert "MISSION COMMANDS" in output
    assert "NOT VERIFIED" in output


def test_dashboard_full_screen_launch_is_only_explicit_tty(monkeypatch):
    tui = __import__("shards_kernel.cli.tui", fromlist=["launch"])
    calls = []
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(mission_control.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(mission_control.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(tui, "launch", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setenv("SHARDS_NO_ANIMATION", "1")
    assert mission_control.run_dashboard(interactive=True) is None
    assert calls == [{"no_animate": True}]


def test_missing_textual_falls_back_without_hiding_internal_import_errors(monkeypatch):
    import builtins

    real_import = builtins.__import__
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(mission_control.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(mission_control.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda prompt: "q")

    def missing_textual(name, *args, **kwargs):
        if name == "shards_kernel.cli.tui":
            raise ModuleNotFoundError("No module named textual", name="textual")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_textual)
    assert mission_control.run_dashboard(interactive=True, no_animate=True) is None

    def broken_internal_dependency(name, *args, **kwargs):
        if name == "shards_kernel.cli.tui":
            raise ModuleNotFoundError("No module named missing_internal", name="missing_internal")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_internal_dependency)
    import pytest

    with pytest.raises(ModuleNotFoundError, match="missing_internal"):
        mission_control.run_dashboard(interactive=True)


def test_optional_rich_fallback_respects_animation_controls(monkeypatch):
    rendered = []
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("SHARDS_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(mission_control.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(mission_control, "_rich_dashboard", lambda **kw: rendered.append(kw))
    assert mission_control.run_dashboard(interactive=False) is None
    assert rendered == [{"animate": True}]
    assert mission_control.run_dashboard(interactive=False, no_animate=True) is None
    assert rendered[-1] == {"animate": False}


def test_plain_interactive_eof_exits_without_dispatch(monkeypatch, capsys):
    def eof(prompt):
        raise EOFError

    monkeypatch.setattr(builtins, "input", eof)
    assert mission_control.run_dashboard(plain=True, interactive=True) is None
    assert "SHARDS // KERNEL" in capsys.readouterr().out


def test_cli_dashboard_dispatches_actual_safe_commands(monkeypatch, capsys):
    from argparse import ArgumentParser
    from shards_kernel.cli import demo

    actions = {"selection": "info"}
    monkeypatch.setattr(
        mission_control, "run_dashboard",
        lambda **kwargs: actions["selection"],
    )
    monkeypatch.setattr(cli, "_cmd_info", lambda variant: 37 if variant == "strict" else 99)
    monkeypatch.setattr(demo, "run_demo", lambda *, json_output: 38 if json_output is False else 99)

    parser = ArgumentParser()
    actions["selection"] = "info"
    assert cli._cmd_dashboard(parser) == 37
    actions["selection"] = "demo"
    assert cli._cmd_dashboard(parser) == 38
    actions["selection"] = "help"
    assert cli._cmd_dashboard(parser) == 0
    assert "usage:" in capsys.readouterr().out.lower()
    actions["selection"] = None
    assert cli._cmd_dashboard(parser) == 0
