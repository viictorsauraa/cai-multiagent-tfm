"""Tests for fix_message_list — specifically the infinite-loop bug fix.

The second pass of fix_message_list reorders tool messages to sit directly
after their parent assistant.  Before the fix, two sibling tool responses
for the same assistant would swap each other indefinitely (pop+insert
no-op cycle).  The relocated_tool_ids guard breaks the cycle.
"""

import signal
import pytest
from cai.util import fix_message_list


def _make_assistant(tool_ids: list[str]) -> dict:
    """Helper: build an assistant message with the given tool_call IDs."""
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": tid,
                "type": "function",
                "function": {"name": f"func_{tid}", "arguments": "{}"},
            }
            for tid in tool_ids
        ],
    }


def _make_tool(tool_call_id: str, content: str = "ok") -> dict:
    return {"role": "tool", "tool_call_id": tool_call_id, "content": content}


def _timeout_handler(signum, frame):
    raise TimeoutError("fix_message_list did not terminate — infinite loop detected")


class TestFixMessageListInfiniteLoop:
    """Regression tests for the pop/insert infinite-swap bug."""

    def test_sibling_tool_responses_no_infinite_loop(self):
        """Two tool responses for the same assistant, displaced by a user
        message, must not cause an infinite loop."""
        messages = [
            _make_assistant(["A", "B"]),
            {"role": "user", "content": "hello"},
            _make_tool("A"),
            _make_tool("B"),
        ]
        # Guard: if fix_message_list hangs, fail after 5 seconds
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(5)
        try:
            result = fix_message_list(messages)
        finally:
            signal.alarm(0)

        # Both tool messages must follow the assistant
        roles = [m["role"] for m in result]
        asst_idx = roles.index("assistant")
        # The two positions right after assistant should be tool messages
        assert result[asst_idx + 1]["role"] == "tool"
        assert result[asst_idx + 2]["role"] == "tool"
        # Both tool IDs should be present
        tool_ids = {result[asst_idx + 1]["tool_call_id"], result[asst_idx + 2]["tool_call_id"]}
        assert tool_ids == {"A", "B"}

    def test_three_sibling_tool_responses(self):
        """Three tool responses for the same assistant — no infinite loop."""
        messages = [
            _make_assistant(["X", "Y", "Z"]),
            {"role": "user", "content": "interleaved"},
            _make_tool("X"),
            _make_tool("Y"),
            _make_tool("Z"),
        ]
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(5)
        try:
            result = fix_message_list(messages)
        finally:
            signal.alarm(0)

        roles = [m["role"] for m in result]
        asst_idx = roles.index("assistant")
        tool_ids = {result[asst_idx + 1 + k]["tool_call_id"] for k in range(3)}
        assert tool_ids == {"X", "Y", "Z"}

    def test_tool_responses_already_in_order(self):
        """When tool responses are already correctly placed, nothing changes."""
        messages = [
            _make_assistant(["A"]),
            _make_tool("A"),
        ]
        result = fix_message_list(messages)
        assert result[0]["role"] == "assistant"
        assert result[1]["role"] == "tool"
        assert result[1]["tool_call_id"] == "A"

    def test_displaced_single_tool_response(self):
        """A single displaced tool response is moved next to its assistant."""
        messages = [
            _make_assistant(["T1"]),
            {"role": "user", "content": "gap"},
            _make_tool("T1"),
        ]
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(5)
        try:
            result = fix_message_list(messages)
        finally:
            signal.alarm(0)

        roles = [m["role"] for m in result]
        asst_idx = roles.index("assistant")
        assert result[asst_idx + 1]["role"] == "tool"
        assert result[asst_idx + 1]["tool_call_id"] == "T1"

    def test_two_assistants_interleaved_tools(self):
        """Tools from different assistants, interleaved — each goes to its own."""
        messages = [
            _make_assistant(["A1"]),
            _make_assistant(["B1"]),
            _make_tool("B1"),
            _make_tool("A1"),
        ]
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(5)
        try:
            result = fix_message_list(messages)
        finally:
            signal.alarm(0)

        # Find each assistant and check its tool follows
        for i, m in enumerate(result):
            if m.get("role") == "assistant" and m.get("tool_calls"):
                expected_id = m["tool_calls"][0]["id"]
                assert result[i + 1]["role"] == "tool"
                assert result[i + 1]["tool_call_id"] == expected_id
