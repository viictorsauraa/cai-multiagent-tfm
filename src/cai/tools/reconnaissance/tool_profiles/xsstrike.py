"""xsstrike tool profile.

XSStrike is a Python-based advanced XSS detection suite. It marks
vulnerabilities with [+] and informational lines with [!]/[*]. This
profile extracts confirmed findings into a concise summary.
"""
import re

from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _xsstrike_post_process(command: str, result: str) -> str:
    """Summarize XSStrike findings (payloads and vulnerable parameters)."""
    findings = []
    for line in result.splitlines():
        stripped = line.strip()
        # XSStrike highlights confirmed vulns with "Payload:" and
        # "Vulnerable webpage:" / "Vector for ..." lines
        if (
            stripped.startswith("Payload:")
            or stripped.startswith("Vulnerable webpage:")
            or stripped.startswith("Vector for")
            or re.match(r"^\[\+\]\s*(Payload|Vulnerable|Reflections)", stripped)
        ):
            findings.append(f"  {stripped}")

    if findings:
        summary = (
            f"\n--- XSSTRIKE FINDINGS ({len(findings)}) ---\n"
            + "\n".join(findings)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="xsstrike",
    pattern=command_pattern("xsstrike"),
    post_process=_xsstrike_post_process,
    idle_timeout=60,
    max_execution_time=600,
    help_indicators=[
        "usage: xsstrike",
        "optional arguments:",
    ],
)
