"""Detect when an agent is stuck repeating the same or similar commands.

Tracks consecutive similar tool commands and signals when the threshold
is reached, allowing the main loop to inject a warning message.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD = 3


@dataclass
class RepetitionDetector:
    """Tracks consecutive similar tool commands per agent.

    Commands are normalized (paths, URLs, and quoted strings replaced
    with placeholders) so that ``ffuf -w /path/a`` and ``ffuf -w /path/b``
    are considered the same command pattern.
    """

    threshold: int = field(
        default_factory=lambda: int(
            os.getenv("CAI_REPEAT_THRESHOLD", str(_DEFAULT_THRESHOLD))
        )
    )
    _history: list[str] = field(default_factory=list, repr=False)
    _warning_issued: bool = field(default=False, repr=False)

    def record(self, command: str) -> None:
        """Record a command.  Resets streak if the pattern changes."""
        normalized = self._normalize(command)
        if self._history and self._history[-1] != normalized:
            self._history.clear()
            self._warning_issued = False
        self._history.append(normalized)

    def should_warn(self) -> bool:
        """Return True if threshold reached and no warning issued yet."""
        if self._warning_issued:
            return False
        return len(self._history) >= self.threshold

    def mark_warned(self) -> None:
        """Mark that a warning has been issued for the current streak."""
        self._warning_issued = True

    def reset(self) -> None:
        """Reset all state (call on agent handoff)."""
        self._history.clear()
        self._warning_issued = False

    @staticmethod
    def _normalize(command: str) -> str:
        """Normalize a command for similarity comparison.

        Replaces file paths, URLs, and quoted strings with placeholders
        so that only the tool name and flags matter for comparison.
        """
        # Replace quoted strings
        s = re.sub(r"['\"].*?['\"]", "<STR>", command)
        # Replace absolute paths
        s = re.sub(r"/[\w./-]+", "<PATH>", s)
        # Replace URLs
        s = re.sub(r"https?://\S+", "<URL>", s)
        # Collapse whitespace
        s = re.sub(r"\s+", " ", s).strip()
        return s


def extract_last_commands(message_history: list[dict]) -> list[str]:
    """Extract command strings from the most recent tool_calls in message_history.

    Only extracts ``generic_linux_command`` calls from the last assistant
    message that contains tool_calls.
    """
    commands: list[str] = []
    for msg in reversed(message_history):
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                func = tc.get("function", {})
                if func.get("name") == "generic_linux_command":
                    try:
                        args = json.loads(func.get("arguments", "{}"))
                        cmd = args.get("command", "")
                        if cmd:
                            commands.append(cmd)
                    except (json.JSONDecodeError, AttributeError):
                        pass
            break  # Only look at the most recent assistant message with tool_calls
    return commands
