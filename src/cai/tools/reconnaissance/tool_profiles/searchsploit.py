"""searchsploit tool profile.

Post-processing: extracts exploit matches from searchsploit output into
a clean summary with exploit paths.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _searchsploit_post_process(command: str, result: str) -> str:
    """Extract exploit entries from searchsploit output."""
    exploits = []
    for line in result.splitlines():
        # searchsploit output: Title  |  Path
        # Lines with | separator and containing exploits/ or shellcodes/
        if "|" in line and re.search(r"(exploits|shellcodes)/", line):
            parts = line.split("|", 1)
            title = parts[0].strip()
            path = parts[1].strip() if len(parts) > 1 else ""
            exploits.append(f"  {title:60s} {path}")

    if exploits:
        summary = (
            f"\n--- EXPLOITS FOUND ({len(exploits)}) ---\n"
            + "\n".join(exploits)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="searchsploit",
    pattern=command_pattern("searchsploit"),
    post_process=_searchsploit_post_process,
)
