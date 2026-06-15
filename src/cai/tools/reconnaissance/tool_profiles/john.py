"""John the Ripper tool profile.

Post-processing: extracts cracked passwords from john's output.
Smart defaults: when john is run with --show on a pot file, no changes.
When run without --wordlist and without --show/--list/--incremental,
warns that no wordlist is specified (john's default wordlist is tiny).
"""
import re
from cai.tools.reconnaissance.tool_profiles import ToolProfile


def _john_smart_defaults(command: str) -> str:
    """Warn-by-appending when no attack mode is specified.

    John without --wordlist, --incremental, --rules, --show, or --list
    uses a tiny built-in wordlist that rarely cracks anything. We append
    a common wordlist path if available and no mode is specified.
    """
    mode_flags = ["--wordlist", "--incremental", "--rules", "--show",
                  "--list", "--single", "--mask", "--prince", "--stdin"]
    has_mode = any(f in command for f in mode_flags)
    if not has_mode:
        command = command.rstrip() + " --wordlist=/usr/share/wordlists/rockyou.txt"
    return command


def _john_post_process(command: str, result: str) -> str:
    """Extract cracked passwords from john output."""
    cracked = []
    for line in result.splitlines():
        # john --show format: user:password  or  hash:password
        # john cracking format: password     (username)
        m = re.match(r"^(\S+)\s+\((.+)\)\s*$", line)
        if m:
            cracked.append(f"  {m.group(2)}:{m.group(1)}")

    if cracked:
        summary = (
            f"\n--- CRACKED PASSWORDS ({len(cracked)}) ---\n"
            + "\n".join(cracked)
        )
        return result + summary
    return result


PROFILE = ToolProfile(
    name="john",
    pattern=r"(?:^|&&|;|\|\|?|\bsudo\s+)\s*john\b",
    smart_defaults=_john_smart_defaults,
    smart_defaults_enabled=True,
    post_process=_john_post_process,
)
