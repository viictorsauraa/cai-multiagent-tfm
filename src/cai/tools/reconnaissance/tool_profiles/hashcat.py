"""hashcat tool profile.

Post-processing: extracts cracked hashes from hashcat output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _hashcat_post_process(command: str, result: str) -> str:
    """Extract cracked hashes from hashcat output."""
    cracked = []
    for line in result.splitlines():
        # hashcat shows cracked as: hash:plaintext
        # Also shows in status: Recovered........: X/Y
        if re.match(r"^[a-fA-F0-9\$\.\/]{8,}:.+$", line):
            cracked.append(f"  {line.strip()}")

    if cracked:
        summary = (
            f"\n--- CRACKED HASHES ({len(cracked)}) ---\n"
            + "\n".join(cracked)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="hashcat",
    pattern=command_pattern("hashcat"),
    post_process=_hashcat_post_process,
)
