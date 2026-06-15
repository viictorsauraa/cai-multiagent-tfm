"""
Tool profiles for generic_linux_command auto-enhancement.

Each profile is a separate .py file in this directory that exports
a module-level PROFILE variable of type ToolProfile.
Profiles are auto-discovered at import time via pkgutil.

Design principle: the LLM chooses command options. Profiles only
intervene via smart_defaults when WITHOUT them the tool would fail
(e.g. sqlmap CRITICAL error). Non-interactive flags like --batch
are the model's responsibility.
"""
import importlib
import logging
import os
import pkgutil
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


def command_pattern(name: str) -> str:
    """Build a regex that matches *name* only as the executed binary.

    Matches at the start of the string, after command chaining operators
    (``&&``, ``;``, ``|``, ``||``), after ``sudo`` or ``python``/``python3``
    (for tools invoked as scripts), or at the end of an absolute path
    (e.g. ``/home/user/go/bin/dalfox``).  Does NOT match *name* when it
    appears as a middle path component (e.g. ``/usr/share/wordlists/dirb/``).
    """
    return (
        rf"(?:^|&&|;|\|\|?|\bsudo\s+|\bpython[0-9.]*\s+|/)"
        rf"\s*{re.escape(name)}\b(?!/)"
    )


@dataclass
class ToolProfile:
    """Declarative enhancement profile for a CLI tool.

    Attributes:
        name:        Human-readable tool name (e.g. "sqlmap").
        pattern:     Regex that must match the command string for this
                     profile to activate.  Typically r"\\bsqlmap\\b".
        smart_defaults:
                     Optional callable receiving the command string and
                     returning a (possibly modified) command string.
                     Only runs if smart_defaults_enabled is True.
        smart_defaults_enabled:
                     Whether smart_defaults should run. Default False.
                     Set True only when without them the tool would fail.
        post_process:
                     Optional callable receiving (command, result) and
                     returning a (possibly modified) result string.
                     Runs after command execution, before guardrails.
        priority:    Lower numbers run first.  Default 100.
        idle_timeout:
                     Idle detection timeout in seconds. The process is
                     terminated if no stdout is produced for this long.
                     Default 10.  Increase for tools like sqlmap that go
                     silent during time-based blind SQL injection.
        max_execution_time:
                     Maximum total execution time in seconds.  0 means
                     no limit (default).  The process is killed after
                     this time regardless of output activity.
        help_indicators:
                     List of strings that, if ALL found in command output,
                     indicate the tool printed its help/usage page instead
                     of real results.  When detected, apply_post replaces
                     the output with a clear error message.
    """
    name: str
    pattern: str
    smart_defaults: Optional[Callable[[str], str]] = None
    smart_defaults_enabled: bool = False
    post_process: Optional[Callable[[str, str], str]] = None
    priority: int = 100
    idle_timeout: int = 10
    max_execution_time: int = 0
    help_indicators: List[str] = field(default_factory=list)

    _compiled: Optional[re.Pattern] = field(
        default=None, init=False, repr=False, compare=False
    )

    def matches(self, command: str) -> bool:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern)
        return bool(self._compiled.search(command))

    def apply_pre(self, command: str) -> str:
        if self.smart_defaults is not None and self.smart_defaults_enabled:
            command = self.smart_defaults(command)
        return command

    def is_help_output(self, result: str) -> bool:
        """Return True if result looks like a help/usage page."""
        if not self.help_indicators:
            return False
        return all(indicator in result for indicator in self.help_indicators)

    def apply_post(self, command: str, result: str) -> str:
        if self.is_help_output(result):
            return (
                f"ERROR: {self.name} printed its help/usage page instead of "
                f"running the actual scan. This usually means a required "
                f"argument is missing or a file path is wrong (e.g., wordlist "
                f"file not found at the specified path). "
                f"Do NOT retry with the same parameters. Either: "
                f"(1) verify the command syntax and arguments/parameters are correct, "
                f"(2) verify the file paths exist (e.g., ls /usr/share/wordlists/), "
                f"(3) use a different wordlist path, or "
                f"(4) try a completely different tool."
            )
        if self.post_process is not None:
            return self.post_process(command, result)
        return result


# ── Registry ────────────────────────────────────────────────────────
_PROFILES: Optional[List[ToolProfile]] = None


def _discover_profiles() -> List[ToolProfile]:
    """Scan this package for modules exporting a PROFILE variable."""
    profiles: List[ToolProfile] = []
    package = __name__
    prefix = package + "."

    for _importer, modname, ispkg in pkgutil.iter_modules(__path__, prefix):
        if ispkg:
            continue
        module_short = modname.replace(prefix, "")
        if module_short.startswith("_"):
            continue
        try:
            module = importlib.import_module(modname)
            profile = getattr(module, "PROFILE", None)
            if isinstance(profile, ToolProfile):
                profiles.append(profile)
        except Exception as exc:
            logger.warning("Failed to load tool profile %s: %s", modname, exc)

    profiles.sort(key=lambda p: p.priority)
    return profiles


def get_profiles() -> List[ToolProfile]:
    """Return the list of discovered profiles (cached after first call)."""
    global _PROFILES
    if _PROFILES is None:
        _PROFILES = _discover_profiles()
    return _PROFILES


def _smart_defaults_globally_enabled() -> bool:
    """Check CAI_TOOL_SMART_DEFAULTS env var (default: true)."""
    return os.getenv("CAI_TOOL_SMART_DEFAULTS", "true").lower() != "false"


def apply_profiles_pre(command: str) -> str:
    """Find the first matching profile and apply pre-processing."""
    if not _smart_defaults_globally_enabled():
        return command
    for profile in get_profiles():
        if profile.matches(command):
            return profile.apply_pre(command)
    return command


def apply_profiles_post(command: str, result: str) -> str:
    """Find the first matching profile and apply post-processing."""
    for profile in get_profiles():
        if profile.matches(command):
            return profile.apply_post(command, result)
    return result


def get_idle_timeout(command: str) -> int:
    """Return the idle_timeout for the first matching profile, or 10."""
    for profile in get_profiles():
        if profile.matches(command):
            return profile.idle_timeout
    return 10


def get_max_execution_time(command: str) -> int:
    """Return max_execution_time for the first matching profile, or 0."""
    for profile in get_profiles():
        if profile.matches(command):
            return profile.max_execution_time
    return 0
