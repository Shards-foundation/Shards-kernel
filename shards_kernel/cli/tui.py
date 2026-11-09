"""Optional interactive Shards-Kernel operator interface.

Presentation-only TUI: no service startup, agent communication, or permit issuance.
Dependencies are loaded only if the optional tui extra was installed.
"""

from __future__ import annotations

from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, Header, RichLog, Static

from shards_kernel._version import __version__


class MissionControlApp(App[None]):
    """Narrow-terminal-first dashboard with read-only, explicitly invoked actions."""

    TITLE = "SHARDS // KERNEL"
    SUB_TITLE = "Mission Control | Local operator interface"
    BINDINGS = [
        ("1", "info", "Kernel"),
        ("2", "diagnostics", "Preflight"),
        ("3", "demo", "Offline demo"),
        ("4", "reference", "Commands"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]
    CSS = """
    Screen { background: #060e18; color: #c4e5f0; }
    Header { background: #0b2333; color: #69ecf8; }
    Footer { background: #0b2333; }
    #body { padding: 0 1; height: 1fr; }
    #banner {
        margin: 1 0 0 0; height: 4; padding: 0 1;
        border: round #3198ab; background: #0c1d2d;
        color: #78e8f0; text-style: bold;
    }
    #matrix {
        margin: 0 0 1 0; padding: 0 1; height: 5;
        border: round #25536b; background: #0a1926;
        color: #bdd4e4;
    }
    .command-row { height: 3; }
    Button {
        width: 1fr; min-width: 12; height: 3; margin: 0 1 0 0;
        background: #123548; border: round #26768b;
        color: #cafaff; text-style: bold;
    }
    Button:hover { background: #24617a; }
    Button:focus { background: #215e74; border: round #7af3ff; }
    #events {
        height: 1fr; min-height: 5; margin: 1 0 0 0;
        background: #071520; border: round #28566d;
        padding: 0 1;
    }
    #footnote { height: 2; color: #79a4b4; padding: 0 1; }
    """

    def __init__(self, *, pulse_enabled: bool = True, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.last_action = "welcome"
        self.last_report: dict[str, Any] | None = None
        self._ticks = 0
        self._pulse_enabled = pulse_enabled

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="body"):
            yield Static(
                "SHARDS / KERNEL   v" + __version__ + "\n"
                "PERMIT > DECISION > AUDIT", id="banner"
            )
            yield Static(
                "POLICY: STRICT AVAILABLE   |   ENFORCEMENT: FAIL-CLOSED\n"
                "AUDIT: REQUIRED (STRICT)  |   SERVICE: NOT INSPECTED\n"
                "AGENTS: NOT CONNECTED    |   READINESS: NOT VERIFIED",
                id="matrix",
            )
            with Horizontal(classes="command-row"):
                yield Button("01 KERNEL", id="info")
                yield Button("02 PREFLIGHT", id="diagnostics")
            with Horizontal(classes="command-row"):
                yield Button("03 DEMO", id="demo")
                yield Button("04 COMMANDS", id="reference")
            yield RichLog(id="events", highlight=False, markup=False, wrap=True)
            yield Static("INTERFACE INITIALISING // LOCAL DATA ONLY", id="footnote")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#events", RichLog).write("SHARDS FOUNDATION | OPERATOR CONSOLE")
        self.query_one("#events", RichLog).write(
            "No external issuer, agent or audit-ledger stream is connected."
        )
        if self._pulse_enabled:
            self.set_interval(0.9, self._pulse)
        self._pulse()

    def _pulse(self) -> None:
        self._ticks += 1
        symbol = "◆" if self._ticks % 2 else "◇"
        self.query_one("#footnote", Static).update(
            symbol + " INTERFACE ACTIVE // no network services checked"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "info": self.action_info,
            "diagnostics": self.action_diagnostics,
            "demo": self.action_demo,
            "reference": self.action_reference,
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            action()

    def _log(self, *lines: str) -> None:
        log = self.query_one("#events", RichLog)
        for line in lines:
            log.write(line)

    def action_info(self) -> None:
        self.last_action = "info"
        self._log(
            "[KERNEL] v" + __version__ + " | Strict profile available",
            "Policy properties: fail-closed, jurisdiction required, audit required.",
            "This is a local capability summary, not an active service status.",
        )

    def action_diagnostics(self) -> None:
        self.last_action = "diagnostics"
        try:
            from shards_kernel.cli.doctor import diagnose

            library = diagnose(profile="library")
            service = diagnose(profile="service")
            self.last_report = {"library": library, "service": service}
            self._log("[PREFLIGHT] Explicit local environment check")
            for profile, report in (("library", library), ("service", service)):
                self._log(profile.upper() + ": " + report["assessment"])
                for check in report["checks"]:
                    self._log("  " + check["status"] + " " + check["id"])
            self._log("Scope: preflight only; deployment readiness NOT VERIFIED.")
        except Exception as exc:
            self.last_report = None
            self._log("[PREFLIGHT] ERROR (" + type(exc).__name__ + ")")

    def action_demo(self) -> None:
        self.last_action = "demo"
        try:
            from shards_kernel.cli.demo import run_scenario

            report = run_scenario()
            self.last_report = {"demo": report}
            self._log("[OFFLINE DEMO] Single-process test only")
            for check in report["checks"]:
                state = "PASS" if check["passed"] else "FAIL"
                self._log("  " + state + " " + check["id"] + " / " + check["observed"])
            self._log("Overall: " + ("PASS" if report["passed"] else "FAIL"))
            self._log("Demo is NOT a production-readiness certification.")
        except ImportError:
            self._log("[DEMO] Crypto extra missing: pip install 'shards-kernel[crypto]'")
        except Exception as exc:
            self._log("[DEMO] ERROR (" + type(exc).__name__ + ")")

    def action_reference(self) -> None:
        self.last_action = "reference"
        self._log(
            "[COMMAND REFERENCE]",
            "shards-kernel info --variant strict",
            "shards-kernel doctor --profile service --json",
            "shards-kernel demo --json",
            "shards-kernel dashboard --plain --no-interactive",
            "No remote execution or account control is provided by this screen.",
        )

    def action_refresh(self) -> None:
        self.last_action = "refresh"
        self._log("[REFRESH] Interface state updated. Press 2 to rerun local preflight.")


def launch(*, no_animate: bool = False) -> None:
    """Launch only after a terminal and the optional Textual extra are present."""
    MissionControlApp(pulse_enabled=not no_animate).run()


if __name__ == "__main__":
    # A downloaded copy can run against an already-installed 0.1.3 kernel.
    # The full integrated CLI is still pending release.
    launch()
