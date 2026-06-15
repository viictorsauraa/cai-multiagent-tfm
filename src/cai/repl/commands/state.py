"""
State command for CAI REPL.
This module provides commands for managing the state.txt findings file.
"""

import os

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from cai.repl.commands.base import Command, register_command
from cai.tools.misc.reasoning import _state_file_path

console = Console()


def _state_path() -> str:
    """Return the absolute path to state.txt, using workspace-aware resolution."""
    return _state_file_path()


class StateCommand(Command):
    """Command to manage the state.txt findings file."""

    def __init__(self):
        """Initialize the state command."""
        super().__init__(
            name="/state",
            description="Manage state.txt findings file (show, clear, write, path)",
            aliases=["/findings"],
        )

        self.add_subcommand("show", "Show current state.txt contents", self.handle_show)
        self.add_subcommand("clear", "Clear state.txt", self.handle_clear)
        self.add_subcommand("write", "Overwrite state.txt with new content", self.handle_write)
        self.add_subcommand("path", "Show state.txt file path", self.handle_path)

    def handle(self, args=None, messages=None):
        """Handle the state command.

        Args:
            args: Command arguments
            messages: Optional list of conversation messages (unused)

        Returns:
            True if the command was handled successfully
        """
        if not args:
            return self.handle_show([])

        subcmd = args[0].lower()
        if subcmd in self.subcommands:
            return self.subcommands[subcmd]["handler"](args[1:] if len(args) > 1 else [])

        # Unknown subcommand — treat as show
        return self.handle_show(args)

    def handle_show(self, args=None):
        """Show state.txt contents."""
        path = _state_path()
        if not os.path.isfile(path):
            console.print(
                Panel(
                    "No state.txt file found. No findings have been recorded.",
                    title="[bold cyan]State - Findings[/bold cyan]",
                    border_style="blue",
                    padding=(1, 2),
                )
            )
            return True

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            console.print(f"[red]Error reading state.txt: {e}[/red]")
            return False

        if not content.strip():
            console.print(
                Panel(
                    "state.txt exists but is empty.",
                    title="[bold cyan]State - Findings[/bold cyan]",
                    border_style="blue",
                    padding=(1, 2),
                )
            )
            return True

        console.print(
            Panel(
                Syntax(content, "text", theme="monokai", word_wrap=True),
                title="[bold cyan]State - Findings[/bold cyan]",
                subtitle=f"[dim]{path}[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        return True

    def handle_clear(self, args=None):
        """Delete state.txt file."""
        path = _state_path()
        if not os.path.isfile(path):
            console.print(
                Panel(
                    "No state.txt file to clear.",
                    title="[bold cyan]State - Clear[/bold cyan]",
                    border_style="blue",
                    padding=(1, 2),
                )
            )
            return True

        try:
            size = os.path.getsize(path)
            os.remove(path)
            console.print(
                Panel(
                    f"Removed state.txt ({size} bytes).",
                    title="[bold cyan]State - Cleared[/bold cyan]",
                    border_style="green",
                    padding=(1, 2),
                )
            )
        except OSError as e:
            console.print(f"[red]Error removing state.txt: {e}[/red]")
            return False

        return True

    def handle_write(self, args=None):
        """Overwrite state.txt with provided content."""
        if not args:
            console.print("[red]Error: Content required[/red]")
            console.print("Usage: /state write <content>")
            return False

        content = " ".join(args)
        path = _state_path()

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            console.print(
                Panel(
                    f"Wrote {len(content)} characters to state.txt.",
                    title="[bold cyan]State - Written[/bold cyan]",
                    border_style="green",
                    padding=(1, 2),
                )
            )
        except OSError as e:
            console.print(f"[red]Error writing state.txt: {e}[/red]")
            return False

        return True

    def handle_path(self, args=None):
        """Show the absolute path to state.txt."""
        path = _state_path()
        exists = os.path.isfile(path)
        status = "[green]exists[/green]" if exists else "[yellow]not found[/yellow]"
        console.print(
            Panel(
                f"{path}\nStatus: {status}",
                title="[bold cyan]State - Path[/bold cyan]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        return True


# Register the /state command
register_command(StateCommand())
