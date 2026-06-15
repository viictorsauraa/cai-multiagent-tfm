"""enum4linux tool profile.

Post-processing: extracts key SMB/NetBIOS enumeration results (shares,
users, groups) from enum4linux's verbose output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _enum4linux_post_process(command: str, result: str) -> str:
    """Extract key enumeration results from enum4linux output."""
    shares = []
    users = []
    groups = []

    for line in result.splitlines():
        stripped = line.strip()
        # Shares: //host/sharename  Mapping: OK  Type: STYPE_DISKTREE
        if re.search(r"//\S+/\S+\s+Mapping:", stripped):
            shares.append(f"  {stripped}")
        # Users: user:[username] rid:[0x...]
        m = re.search(r"user:\[([^\]]+)\]\s+rid:", stripped)
        if m:
            users.append(f"  {m.group(1)}")
        # Groups: group:[groupname] rid:[0x...]
        m = re.search(r"group:\[([^\]]+)\]\s+rid:", stripped)
        if m:
            groups.append(f"  {m.group(1)}")

    parts = []
    if shares:
        parts.append(f"Shares ({len(shares)}):\n" + "\n".join(shares))
    if users:
        parts.append(f"Users ({len(users)}):\n" + "\n".join(users))
    if groups:
        parts.append(f"Groups ({len(groups)}):\n" + "\n".join(groups))

    if parts:
        summary = "\n--- ENUM4LINUX SUMMARY ---\n" + "\n".join(parts)
        return result + summary
    return result


PROFILE = ToolProfile(
    name="enum4linux",
    pattern=command_pattern("enum4linux"),
    post_process=_enum4linux_post_process,
)
