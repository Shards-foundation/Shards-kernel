"""Optional read-only terminal welcome interface. Never runs during installation or import."""

from __future__ import annotations

import os
import sys
import time
from typing import Optional

from shards_kernel._version import __version__

_ACTIONS = {"1": "info", "2": "doctor", "3": "demo", "4": "help"}


def _is_interactive() -> bool:
    return bool(sys.stdout.isatty() and sys.stdin.isatty() and not os.environ.get("CI"))


def _plain_dashboard(*, rich_missing: bool = False) -> None:
    """Dependency-free display for pipes, simple terminals and Termux."""
    print(f"SHARDS // KERNEL  v{__version__}")
    print("Deterministic control plane for governed AI-agent tool execution.")
    print("Policy -> permit -> decision -> auditable execution")
    print()
    print("PROFILE         Strict policy available; no service inspected")
    print("FAIL-CLOSED     Strict profile requires denial on failed checks")
    print("AUDIT           Strict profile requires audit decisions")
    print("LIVE STATUS     NOT VERIFIED (run: shards-kernel doctor)")
    print()
    print("[1] Kernel information     [2] Run preflight diagnostics")
    print("[3] Safe offline demo      [4] Command reference")
    print("[Q] Exit")
    if rich_missing:
        print("\nFor colour panels: pip install 'shards-kernel[tui]'")


def _rich_dashboard(*, animate: bool) -> None:
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console(highlight=False, soft_wrap=False)
    if animate:
        with console.status("[cyan]Initialising operator interface[/cyan]", spinner="dots"):
            time.sleep(0.4)

    wide = console.size.width >= 76
    brand = Text()
    brand.append("SHARDS", style="bold #82F7FF")
    brand.append(" // ", style="bold #1986A6")
    brand.append("KERNEL", style="bold #33D5F5")
    brand.append(f"   v{__version__}", style="#8B9BAB")
    tagline = Text("Deterministic control plane for AI systems", style="#B7D3E4")
    intro = Text.assemble(
        brand, "\n", tagline, "\n",
        Text("PERMIT  >  DECISION  >  AUDIT", style="bold #43CEB6"),
    )
    console.print(Panel(
        intro, title="[bold #36DFFA]SHARDS FOUNDATION[/bold #36DFFA]",
        border_style="#267B9B", padding=(1, 2),
    ))

    statuses = Table.grid(padding=(0, 1), expand=True)
    statuses.add_column(style="#8CAFC4", no_wrap=True)
    statuses.add_column(style="#BEECEB")
    statuses.add_row("POLICY", "STRICT (available)")
    statuses.add_row("ENFORCEMENT", "FAIL-CLOSED (strict)")
    statuses.add_row("AUDIT", "REQUIRED (strict)")
    statuses.add_row("SERVICE", "NOT INSPECTED")
    statuses.add_row("READINESS", "NOT VERIFIED")
    status_panel = Panel(
        statuses, title="[bold cyan]CONTROL MATRIX[/bold cyan]",
        border_style="#27566E", padding=(1, 1),
    )

    actions = Table.grid(padding=(0, 1), expand=True)
    actions.add_column(style="bold #46D5EE", no_wrap=True)
    actions.add_column(style="#D4E4F1")
    actions.add_row("01", "Kernel information")
    actions.add_row("02", "Run preflight diagnostics")
    actions.add_row("03", "Safe offline demo")
    actions.add_row("04", "Command reference")
    actions.add_row(" Q", "Exit")
    action_panel = Panel(
        actions, title="[bold cyan]MISSION COMMANDS[/bold cyan]",
        border_style="#27566E", padding=(1, 1),
    )

    if wide:
        console.print(Columns([status_panel, action_panel], equal=True, expand=True))
    else:
        console.print(status_panel)
        console.print(action_panel)
    console.print("[dim]Read-only welcome screen · No services or agent connectivity checked[/dim]")


def run_dashboard(*, plain: bool = False, no_animate: bool = False,
                  interactive: Optional[bool] = None) -> Optional[str]:
    """Render welcome; return a safe chosen action without executing anything.

    Keeping display and dispatch separate protects JSON, MCP and service stdout.
    """
    if interactive is None:
        interactive = _is_interactive()
    use_plain = (
        plain or not sys.stdout.isatty() or os.environ.get("TERM") == "dumb"
        or "NO_COLOR" in os.environ
    )
    if use_plain:
        _plain_dashboard()
    else:
        try:
            import rich  # noqa: F401
        except ImportError:
            _plain_dashboard(rich_missing=True)
        else:
            animate = (
                not no_animate and not os.environ.get("CI")
                and not os.environ.get("SHARDS_NO_ANIMATION")
            )
            _rich_dashboard(animate=animate)

    if not interactive:
        return None

    try:
        selection = input("shards-kernel > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return _ACTIONS.get(selection)
