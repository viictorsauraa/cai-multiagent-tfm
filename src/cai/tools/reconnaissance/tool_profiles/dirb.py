"""dirb tool profile.

Post-processing: extracts discovered URLs from dirb output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _dirb_post_process(command: str, result: str) -> str:
    """Extract discovered URLs from dirb output."""
    found = []
    for line in result.splitlines():
        # dirb output: + http://target/path (CODE:200|SIZE:1234)
        m = re.match(r"^\+\s+(https?://\S+)\s+\(CODE:(\d+)", line)
        if m:
            found.append(f"  {m.group(1):50s} [{m.group(2)}]")

    if found:
        summary = (
            f"\n--- DISCOVERED URLS ({len(found)}) ---\n"
            + "\n".join(found)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="dirb",
    pattern=command_pattern("dirb"),
    post_process=_dirb_post_process,
    help_indicators=["----- DIRB", "By The Dark Raver"],
)
