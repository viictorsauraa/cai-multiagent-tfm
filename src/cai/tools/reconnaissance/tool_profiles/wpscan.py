"""wpscan tool profile.

Post-processing: extracts vulnerabilities and interesting findings from
WPScan's verbose output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _wpscan_post_process(command: str, result: str) -> str:
    """Extract vulnerabilities and findings from wpscan output."""
    vulns = []
    for line in result.splitlines():
        stripped = line.strip()
        # WPScan marks vulnerabilities with [!] and interesting findings with [+]
        if stripped.startswith("[!]"):
            vulns.append(f"  {stripped}")
        elif "Title:" in stripped and "vulnerability" not in stripped.lower():
            vulns.append(f"  {stripped}")

    if vulns:
        summary = (
            f"\n--- WPSCAN FINDINGS ({len(vulns)}) ---\n"
            + "\n".join(vulns)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="wpscan",
    pattern=command_pattern("wpscan"),
    post_process=_wpscan_post_process,
)
