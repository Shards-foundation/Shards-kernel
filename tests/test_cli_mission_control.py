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
