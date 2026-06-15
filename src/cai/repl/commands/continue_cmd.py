"""
Continue command for CAI REPL.
This module provides commands for managing auto-continue mode at runtime.
"""

from rich.console import Console
from rich.panel import Panel

from cai.repl.commands.base import Command, register_command

console = Console()


class _ContinueState:
    """Module-level state for continue mode, shared with cli.py."""

    def __init__(self):
        self.enabled: bool = False
        self.pending_input: str | None = None


CONTINUE_STATE = _ContinueState()


class ContinueCommand(Command):
    """Command to manage auto-continue mode."""

    def __init__(self):
        """Initialize the continue command."""
        super().__init__(
            name="/continue",
            description="Toggle or manage auto-continue mode (on, off, status)",
            aliases=["/cont"],
        )

        self.add_subcommand("on", "Enable auto-continue mode", self.handle_on)
        self.add_subcommand("off", "Disable auto-continue mode", self.handle_off)
        self.add_subcommand("status", "Show current auto-continue status", self.handle_status)

    def handle(self, args=None, messages=None):
        """Handle the continue command.

        Args:
            args: Command arguments
            messages: Optional list of conversation messages (unused)

        Returns:
            True if the command was handled successfully
        """
        if not args:
            return self.handle_toggle()

        subcmd = args[0].lower()
        if subcmd in self.subcommands:
            return self.subcommands[subcmd]["handler"](args[1:] if len(args) > 1 else [])

        return self.handle_unknown_subcommand(subcmd)

    def handle_toggle(self):
        """Toggle auto-continue mode."""
        CONTINUE_STATE.enabled = not CONTINUE_STATE.enabled
        status = "ON" if CONTINUE_STATE.enabled else "OFF"
        color = "green" if CONTINUE_STATE.enabled else "red"
        if not CONTINUE_STATE.enabled:
            CONTINUE_STATE.pending_input = None
        console.print(Panel(
            f"Auto-continue mode: [{color}]{status}[/{color}]",
            title="[bold cyan]Continue Mode[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        ))
        return True

    def handle_on(self, args=None):
        """Enable auto-continue mode."""
        CONTINUE_STATE.enabled = True
        console.print(Panel(
            "Auto-continue mode: [green]ON[/green]",
            title="[bold cyan]Continue Mode[/bold cyan]",
            border_style="green",
            padding=(0, 2),
        ))
        return True

    def handle_off(self, args=None):
        """Disable auto-continue mode."""
        CONTINUE_STATE.enabled = False
        CONTINUE_STATE.pending_input = None
        console.print(Panel(
            "Auto-continue mode: [red]OFF[/red]\nPending input cleared.",
            title="[bold cyan]Continue Mode[/bold cyan]",
            border_style="red",
            padding=(0, 2),
        ))
        return True

    def handle_status(self, args=None):
        """Show current auto-continue status."""
        status = "[green]ON[/green]" if CONTINUE_STATE.enabled else "[red]OFF[/red]"
        pending = CONTINUE_STATE.pending_input or "[dim]None[/dim]"
        console.print(Panel(
            f"Enabled: {status}\nPending input: {pending}",
            title="[bold cyan]Continue Mode - Status[/bold cyan]",
            border_style="blue",
            padding=(0, 2),
        ))
        return True


# Register the /continue command
register_command(ContinueCommand())
