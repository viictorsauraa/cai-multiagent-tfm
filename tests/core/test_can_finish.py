"""Tests for the can_finish agent field.

Verifies that:
- can_finish defaults to True
- can_finish=False is preserved across clones
- redteam_orchestrated specialists have can_finish=False
- Orchestrator and Report have can_finish=True
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from cai.sdk.agents import Agent


class TestCanFinishField:
    """Basic field behavior on the Agent dataclass."""

    def test_default_is_true(self):
        agent = Agent(name="test")
        assert agent.can_finish is True

    def test_can_set_false(self):
        agent = Agent(name="test", can_finish=False)
        assert agent.can_finish is False

    def test_clone_preserves_can_finish(self):
        agent = Agent(name="test", can_finish=False)
        clone = agent.clone()
        assert clone.can_finish is False

    def test_clone_can_override_can_finish(self):
        agent = Agent(name="test", can_finish=False)
        clone = agent.clone(can_finish=True)
        assert clone.can_finish is True


class TestRedteamCanFinish:
    """Verify redteam_orchestrated pattern configuration."""

    def test_specialists_cannot_finish(self):
        from cai.agents.patterns.redteam_orchestrated import (
            _recon, _strategy, _exploitation, _privesc,
        )
        for agent in [_recon, _strategy, _exploitation, _privesc]:
            assert agent.can_finish is False, (
                f"{agent.name} should have can_finish=False"
            )

    def test_orchestrator_and_report_can_finish(self):
        from cai.agents.patterns.redteam_orchestrated import (
            _orchestrator, _report,
        )
        assert _orchestrator.can_finish is True
        assert _report.can_finish is True


class TestCanFinishNoHandoffsWarning:
    """can_finish=False with no handoffs should log a warning."""

    @pytest.mark.asyncio
    async def test_logs_warning_when_no_handoffs(self, caplog):
        import logging
        from unittest.mock import MagicMock
        from cai.sdk.agents._run_impl import RunImpl
        from cai.sdk.agents.items import ModelResponse

        agent = Agent(name="test_agent", can_finish=False, handoffs=[])
        mock_response = MagicMock(spec=ModelResponse)
        mock_context = MagicMock()

        with caplog.at_level(logging.WARNING):
            result = await RunImpl._maybe_force_handoff(
                agent, "input", mock_response, [], [], mock_context,
            )

        assert result is None  # No handoff possible
        assert "can_finish=False but no handoffs" in caplog.text
