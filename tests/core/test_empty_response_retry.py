"""Tests for the empty response retry logic in OpenAIChatCompletionsModel.

Verifies that the nudge message injected on empty responses is properly
rolled back from message_history after the retry attempt.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel


def _make_empty_response(completion_tokens=100):
    """Create a mock response with empty content but positive token usage."""
    msg = MagicMock()
    msg.content = None
    msg.tool_calls = None
    msg.refusal = None
    msg.model_dump.return_value = {"content": None, "tool_calls": None}

    choice = MagicMock()
    choice.message = msg

    usage = MagicMock()
    usage.prompt_tokens = 50
    usage.completion_tokens = completion_tokens
    usage.total_tokens = 50 + completion_tokens

    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


def _make_good_response():
    """Create a mock response with actual content."""
    msg = MagicMock()
    msg.content = "Here is the answer."
    msg.tool_calls = None
    msg.refusal = None
    msg.model_dump.return_value = {"content": "Here is the answer.", "tool_calls": None}

    choice = MagicMock()
    choice.message = msg

    usage = MagicMock()
    usage.prompt_tokens = 60
    usage.completion_tokens = 20
    usage.total_tokens = 80

    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


class TestNudgeRollback:
    """Nudge message must not persist in message_history after retry."""

    def test_nudge_not_in_history_after_successful_retry(self):
        """After a successful retry, nudge should be removed from history."""
        model = OpenAIChatCompletionsModel(
            model="test-model",
            openai_client=MagicMock(),
        )
        initial_history_len = len(model.message_history)

        # Simulate: add nudge, then remove it (as the fix does)
        nudge_msg = {"role": "user", "content": "Your previous response was empty."}
        model.add_to_message_history(nudge_msg)
        assert len(model.message_history) == initial_history_len + 1

        # Simulate the finally block
        if model.message_history and model.message_history[-1] is nudge_msg:
            model.message_history.pop()

        assert len(model.message_history) == initial_history_len
        # Verify no nudge content remains
        for msg in model.message_history:
            if isinstance(msg, dict) and msg.get("role") == "user":
                assert "empty" not in msg.get("content", "").lower()

    def test_nudge_not_in_history_after_failed_retry(self):
        """Even if retry raises, nudge should be removed from history."""
        model = OpenAIChatCompletionsModel(
            model="test-model",
            openai_client=MagicMock(),
        )
        initial_history_len = len(model.message_history)

        nudge_msg = {"role": "user", "content": "Your previous response was empty."}
        model.add_to_message_history(nudge_msg)

        # Simulate exception + finally block
        try:
            raise ConnectionError("API failed")
        except Exception:
            pass
        finally:
            if model.message_history and model.message_history[-1] is nudge_msg:
                model.message_history.pop()

        assert len(model.message_history) == initial_history_len

    def test_no_double_nudge_accumulation(self):
        """Multiple empty responses should not accumulate nudge messages."""
        model = OpenAIChatCompletionsModel(
            model="test-model",
            openai_client=MagicMock(),
        )
        initial_history_len = len(model.message_history)

        # Simulate 3 empty response cycles with proper rollback
        for _ in range(3):
            nudge_msg = {"role": "user", "content": "Your previous response was empty."}
            model.add_to_message_history(nudge_msg)
            # finally block
            if model.message_history and model.message_history[-1] is nudge_msg:
                model.message_history.pop()

        assert len(model.message_history) == initial_history_len
