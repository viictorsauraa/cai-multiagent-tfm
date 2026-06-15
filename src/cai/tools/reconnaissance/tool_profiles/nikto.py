"""nikto tool profile.

Post-processing: extracts a summary of findings from nikto's verbose output.
Nikto produces a lot of informational lines; the summary helps the LLM
focus on actionable results.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _nikto_post_process(command: str, result: str) -> str:
    """Append a summary of nikto findings."""
    findings = []
    for line in result.splitlines():
        # Nikto findings start with "+ " and contain OSVDB or vulnerability info
        if re.match(r"^\+ (?!Target|Server|Start|End|\d+ host)", line):
            findings.append(f"  {line.strip()}")

    if findings:
        summary = (
            f"\n--- NIKTO FINDINGS SUMMARY ({len(findings)} items) ---\n"
            + "\n".join(findings)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="nikto",
    pattern=command_pattern("nikto"),
    post_process=_nikto_post_process,
)
