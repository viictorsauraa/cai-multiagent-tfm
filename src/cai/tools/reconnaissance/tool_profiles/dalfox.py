"""dalfox tool profile.

Dalfox is a Go-based parameter analyzer and XSS scanner. Findings are
marked with [POC], [V] (verified) and [R] (reflected) in its output.
This profile extracts those lines into a concise summary and ensures
dalfox runs non-interactively with a reasonable execution cap.
"""
import re

from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _dalfox_smart_defaults(command: str) -> str:
    """Add --silence when running on a URL to reduce banner noise.

    Skip for help/update/version subcommands and when the user has
    explicitly requested verbose output.
    """
    skip_flags = ["--help", " -h ", "--version", " version", "update"]
    if any(f in command for f in skip_flags):
        return command
    if "--silence" in command or "-S " in command or command.endswith(" -S"):
        return command
    # Only inject --silence for scanning subcommands
    if re.search(r"\bdalfox\s+(url|pipe|file|sxss|payload)\b", command):
        command = command.rstrip() + " --silence"
    return command


def _dalfox_post_process(command: str, result: str) -> str:
    """Append a summary of verified and PoC findings from dalfox output."""
    findings = []
    for line in result.splitlines():
        stripped = line.strip()
        # Dalfox marks findings with [V], [POC], [R] or [VULN]
        if re.match(r"^\[(V|POC|R|VULN)\]", stripped):
            findings.append(f"  {stripped}")

    if findings:
        summary = (
            f"\n--- DALFOX XSS FINDINGS ({len(findings)}) ---\n"
            + "\n".join(findings)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="dalfox",
    pattern=command_pattern("dalfox"),
    smart_defaults=_dalfox_smart_defaults,
    smart_defaults_enabled=True,
    post_process=_dalfox_post_process,
    idle_timeout=60,
    max_execution_time=600,
    help_indicators=[
        "Usage:",
        "dalfox [command]",
        "Available Commands:",
    ],
)
