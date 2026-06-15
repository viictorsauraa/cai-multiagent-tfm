"""gobuster tool profile.

Post-processing: extracts discovered directories/files from gobuster output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _gobuster_post_process(command: str, result: str) -> str:
    """Extract discovered paths from gobuster output."""
    found = []
    for line in result.splitlines():
        # gobuster dir: /path  (Status: 200) [Size: 1234]
        m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
        if m:
            found.append(f"  {m.group(1):40s} [{m.group(2)}]")

    if found:
        summary = (
            f"\n--- DISCOVERED PATHS ({len(found)}) ---\n"
            + "\n".join(found)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="gobuster",
    pattern=command_pattern("gobuster"),
    post_process=_gobuster_post_process,
    help_indicators=["Usage:", "gobuster [command]"],
)
