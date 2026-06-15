"""sqlmap tool profile.

Smart defaults enabled: when the URL has no explicit GET parameters (?),
sqlmap exits with [CRITICAL] no parameter(s) found. Adding --forms and
--crawl=2 allows sqlmap to discover injection points automatically.
"""
import re

from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _sqlmap_smart_defaults(command: str) -> str:
    """Add --forms and --crawl=2 when URL has no explicit GET parameters."""
    # Skip non-scan modes where adding discovery flags makes no sense
    skip_flags = ["--help", "-h ", "-hh", "-r ", "--request", "--wizard", "--update"]
    if any(f in command for f in skip_flags):
        return command
    # Skip when POST data is already specified — injection points are explicit
    if "--data" in command:
        return command
    # Skip when a tamper script is in use — the injection point is encoded
    # inside the tamper (e.g. JWT kid via a custom tamper), so crawling
    # forms is irrelevant and would distort the scan.
    if "--tamper" in command:
        return command
    # Check if URL (after -u/--url) already contains a query string
    url_match = re.search(r'(?:-u|--url)\s+["\']?(\S+)', command)
    if url_match:
        url = url_match.group(1).strip("\"'")
        if "?" in url:
            return command  # URL already has GET params
    # No URL with params found — add discovery flags
    if "--forms" not in command:
        command = command.rstrip() + " --forms"
    if "--crawl" not in command:
        command = command.rstrip() + " --crawl=2"
    return command


PROFILE = ToolProfile(
    name="sqlmap",
    pattern=command_pattern("sqlmap"),
    smart_defaults=_sqlmap_smart_defaults,
    smart_defaults_enabled=True,
    idle_timeout=120,
    max_execution_time=900,
)
