"""nmap tool profile.

Post-processing: extracts a concise summary of open ports and services
from nmap's verbose output, appended at the end for quick parsing by the LLM.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _nmap_post_process(command: str, result: str) -> str:
    """Append a structured summary of open ports at the end of nmap output."""
    lines = result.splitlines()
    open_ports = []
    for line in lines:
        # Match lines like: 80/tcp   open  http    Apache httpd 2.4.49
        m = re.match(r"(\d+/\w+)\s+open\s+(.+)", line)
        if m:
            open_ports.append(f"  {m.group(1):15s} {m.group(2).strip()}")

    if open_ports:
        summary = "\n--- OPEN PORTS SUMMARY ---\n" + "\n".join(open_ports)
        return result + summary
    return result


PROFILE = ToolProfile(
    name="nmap",
    pattern=command_pattern("nmap"),
    post_process=_nmap_post_process,
)
