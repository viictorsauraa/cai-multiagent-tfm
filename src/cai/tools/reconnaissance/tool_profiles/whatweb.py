"""whatweb tool profile.

Post-processing: extracts identified technologies from whatweb output.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _whatweb_post_process(command: str, result: str) -> str:
    """Extract technology fingerprints from whatweb output."""
    techs = []
    for line in result.splitlines():
        stripped = line.strip()
        # WhatWeb output contains bracketed technology identifiers
        # e.g.: http://target [200 OK] Apache[2.4.49], PHP[7.4.3], ...
        if re.match(r"^https?://", stripped) and "[" in stripped:
            # Extract all [Tech] or [Tech][version] entries
            items = re.findall(r"(\w[\w\s.-]*)\[([^\]]*)\]", stripped)
            for tech, version in items:
                tech = tech.strip()
                if version:
                    techs.append(f"  {tech}: {version}")
                else:
                    techs.append(f"  {tech}")

    if techs:
        summary = (
            f"\n--- TECHNOLOGIES DETECTED ({len(techs)}) ---\n"
            + "\n".join(techs)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="whatweb",
    pattern=command_pattern("whatweb"),
    post_process=_whatweb_post_process,
)
