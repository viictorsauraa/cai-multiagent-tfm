"""wfuzz tool profile.

Post-processing: extracts successful fuzzing results from wfuzz output,
filtering out common false positives.
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile, command_pattern


def _wfuzz_post_process(command: str, result: str) -> str:
    """Extract interesting fuzzing results from wfuzz output."""
    hits = []
    for line in result.splitlines():
        # wfuzz output: 000000X:   C=200   L lines   W words   Ch chars   "payload"
        m = re.match(
            r"^\d+:\s+C=(\d+)\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+\"(.+)\"",
            line,
        )
        if m:
            status, lines, words, chars, payload = m.groups()
            hits.append(
                f"  {payload:40s} [Status:{status} Lines:{lines} "
                f"Words:{words} Chars:{chars}]"
            )

    if hits:
        summary = (
            f"\n--- FUZZING HITS ({len(hits)}) ---\n"
            + "\n".join(hits)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="wfuzz",
    pattern=command_pattern("wfuzz"),
    post_process=_wfuzz_post_process,
    help_indicators=["Usage:", "wfuzz [options]"],
)
