"""hydra tool profile.

Post-processing: highlights successfully cracked credentials in the output
so the LLM can immediately identify and use them.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _hydra_post_process(command: str, result: str) -> str:
    """Extract and highlight found credentials from hydra output."""
    creds = []
    for line in result.splitlines():
        # Hydra reports: [22][ssh] host: 10.0.0.1   login: admin   password: secret
        if re.search(r"\]\s+host:.*login:.*password:", line):
            creds.append(f"  {line.strip()}")

    if creds:
        summary = (
            f"\n--- CREDENTIALS FOUND ({len(creds)}) ---\n"
            + "\n".join(creds)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="hydra",
    pattern=command_pattern("hydra"),
    post_process=_hydra_post_process,
    idle_timeout=30,
    max_execution_time=300,
)
