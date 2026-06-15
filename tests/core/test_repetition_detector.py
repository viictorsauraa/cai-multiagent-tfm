"""Tests for the RepetitionDetector and extract_last_commands utilities."""

import os
from cai.sdk.agents.repetition_detector import (
    RepetitionDetector,
    extract_last_commands,
)


class TestRepetitionDetector:
    """Unit tests for RepetitionDetector."""

    def test_triggers_after_threshold(self):
        """Should trigger warning after N consecutive similar commands."""
        det = RepetitionDetector(threshold=3)
        det.record("ffuf -w /path/a -u http://target/FUZZ")
        det.record("ffuf -w /path/b -u http://target/FUZZ")
        assert not det.should_warn()
        det.record("ffuf -w /path/c -u http://target/FUZZ")
        assert det.should_warn()

    def test_resets_on_different_command(self):
        """Streak should reset when a different command is recorded."""
        det = RepetitionDetector(threshold=3)
        det.record("ffuf -w /path/a -u http://target/FUZZ")
        det.record("ffuf -w /path/b -u http://target/FUZZ")
        det.record("nmap -sV 10.0.0.1")  # different tool
        det.record("nmap -sV 10.0.0.2")
        assert not det.should_warn()  # only 2 nmap, not 3

    def test_only_warns_once(self):
        """After warning is issued, should_warn returns False."""
        det = RepetitionDetector(threshold=2)
        det.record("ffuf -w /a -u http://x/FUZZ")
        det.record("ffuf -w /b -u http://x/FUZZ")
        assert det.should_warn()
        det.mark_warned()
        det.record("ffuf -w /c -u http://x/FUZZ")
        assert not det.should_warn()

    def test_reset_clears_everything(self):
        """Reset should clear history and warning flag."""
        det = RepetitionDetector(threshold=2)
        det.record("cmd1")
        det.record("cmd1")
        det.mark_warned()
        det.reset()
        assert not det.should_warn()
        assert len(det._history) == 0

    def test_normalization_ignores_paths(self):
        """Commands with different paths should normalize to the same string."""
        det = RepetitionDetector(threshold=2)
        det.record("gobuster dir -w /usr/share/wordlists/a.txt -u http://target")
        det.record("gobuster dir -w /usr/share/seclists/b.txt -u http://target")
        assert det.should_warn()

    def test_normalization_ignores_urls(self):
        """Commands with different URLs should normalize to the same string."""
        det = RepetitionDetector(threshold=2)
        det.record("nmap -sV http://10.0.0.1")
        det.record("nmap -sV http://10.0.0.2")
        assert det.should_warn()

    def test_normalization_preserves_flags(self):
        """Commands with different flags should NOT be considered similar."""
        det = RepetitionDetector(threshold=2)
        det.record("nmap -sV 10.0.0.1")
        det.record("nmap -p- 10.0.0.1")
        assert not det.should_warn()

    def test_env_var_threshold(self, monkeypatch):
        """Threshold should be configurable via CAI_REPEAT_THRESHOLD."""
        monkeypatch.setenv("CAI_REPEAT_THRESHOLD", "5")
        det = RepetitionDetector()
        assert det.threshold == 5


class TestExtractLastCommands:
    """Tests for extract_last_commands helper."""

    def test_extracts_generic_linux_command(self):
        """Should extract command arg from generic_linux_command tool calls."""
        history = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "generic_linux_command",
                            "arguments": '{"command": "nmap -sV 10.0.0.1", "interactive": false}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "PORT 80/tcp open"},
        ]
        cmds = extract_last_commands(history)
        assert cmds == ["nmap -sV 10.0.0.1"]

    def test_ignores_other_tools(self):
        """Should only extract generic_linux_command, not other tool calls."""
        history = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "transfer_to_recon_agent",
                            "arguments": "{}",
                        },
                    }
                ],
            },
        ]
        cmds = extract_last_commands(history)
        assert cmds == []

    def test_extracts_only_last_assistant_with_tools(self):
        """Should only look at the most recent assistant message with tool_calls."""
        history = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_old",
                        "type": "function",
                        "function": {
                            "name": "generic_linux_command",
                            "arguments": '{"command": "old_cmd"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_old", "content": "old result"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_new",
                        "type": "function",
                        "function": {
                            "name": "generic_linux_command",
                            "arguments": '{"command": "new_cmd"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_new", "content": "new result"},
        ]
        cmds = extract_last_commands(history)
        assert cmds == ["new_cmd"]

    def test_empty_history(self):
        """Empty history should return empty list."""
        assert extract_last_commands([]) == []
