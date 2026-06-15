"""ffuf tool profile.

Post-processing: extracts discovered paths/endpoints from ffuf output
for quick parsing by the LLM.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _ffuf_post_process(command: str, result: str) -> str:
    """Extract discovered endpoints from ffuf output."""
    found = []
    for line in result.splitlines():
        # ffuf output: /path  [Status: 200, Size: 1234, Words: 56, Lines: 78]
        m = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
        if m:
            found.append(f"  {m.group(1):40s} [{m.group(2)}] Size:{m.group(3)}")

    if found:
        summary = (
            f"\n--- DISCOVERED PATHS ({len(found)}) ---\n"
            + "\n".join(found)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="ffuf",
    pattern=command_pattern("ffuf"),
    post_process=_ffuf_post_process,
    help_indicators=["Fuzz Faster U Fool", "HTTP OPTIONS:"],
)
