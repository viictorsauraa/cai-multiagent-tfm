"""Tests for isolated_context: per-agent message history in swarm mode.

Verifies that when agents have isolated_context=True:
1. Each agent keeps its own independent message_history
2. Handoff injects a context summary instead of sharing references
3. generated_items are filtered to include only the current agent's items
4. The original shared-history behavior is preserved when isolated_context=False
"""

from unittest.mock import MagicMock

from cai.sdk.agents.agent import Agent
from cai.sdk.agents.run import (
    _inject_handoff_context,
    _HANDOFF_CONTEXT_MESSAGES,
    _HANDOFF_MSG_TRUNCATE,
)


# ── Fixtures ─────────────────────────────────────────────────────────


def _make_agent(name: str, isolated: bool = True) -> Agent:
    """Create an agent with a mock model that has message_history."""
    agent = Agent(name=name, instructions=f"You are {name}", isolated_context=isolated)
    model = MagicMock()
    model.message_history = []
    agent.model = model
    return agent


def _make_history(messages: list[tuple[str, str]]) -> list[dict]:
    """Build a message_history from (role, content) tuples."""
    return [{"role": role, "content": content} for role, content in messages]


# ── Agent field tests ────────────────────────────────────────────────


class TestIsolatedContextField:
    def test_default_is_false(self):
        agent = Agent(name="test", instructions="test")
        assert agent.isolated_context is False

    def test_can_be_set_true(self):
        agent = Agent(name="test", instructions="test", isolated_context=True)
        assert agent.isolated_context is True

    def test_clone_preserves_isolated_context(self):
        agent = Agent(name="test", instructions="test", isolated_context=True)
        cloned = agent.clone(name="cloned")
        assert cloned.isolated_context is True

    def test_clone_can_override_isolated_context(self):
        agent = Agent(name="test", instructions="test", isolated_context=True)
        cloned = agent.clone(isolated_context=False)
        assert cloned.isolated_context is False


# ── Constants tests ──────────────────────────────────────────────────


class TestConstants:
    def test_default_handoff_context_messages(self):
        assert _HANDOFF_CONTEXT_MESSAGES == 10

    def test_default_handoff_msg_truncate(self):
        assert _HANDOFF_MSG_TRUNCATE == 500


# ── _inject_handoff_context tests ────────────────────────────────────


class TestInjectHandoffContext:
    def test_basic_injection(self):
        """Context from source agent is injected into destination agent."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "Scan 10.0.0.1"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {"name": "generic_linux_command", "arguments": '{"command": "nmap -sV 10.0.0.1"}'}}
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": "PORT 80/tcp open http"},
            {"role": "assistant", "content": "Found HTTP on port 80"},
        ]

        _inject_handoff_context(src, dst)

        assert len(dst.model.message_history) == 1
        ctx = dst.model.message_history[0]
        assert ctx["role"] == "user"
        assert "[Handoff from Recon]" in ctx["content"]
        assert "nmap -sV 10.0.0.1" in ctx["content"]
        assert "Found HTTP on port 80" in ctx["content"]

    def test_system_messages_excluded(self):
        """System messages from the source should not leak into the injection."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = _make_history([
            ("system", "You are a recon specialist. SECRET PROMPT."),
            ("user", "Scan target"),
            ("assistant", "Scanning..."),
        ])

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        assert "SECRET PROMPT" not in ctx
        assert "system" not in ctx.lower().split("[handoff")[0]  # no system role label
        assert "Scanning" in ctx  # assistant conclusion

    def test_histories_are_independent(self):
        """Source and destination histories must not be the same object."""
        src = _make_agent("A")
        dst = _make_agent("B")

        src.model.message_history = _make_history([
            ("user", "hello"),
            ("assistant", "hi"),
        ])

        _inject_handoff_context(src, dst)

        assert src.model.message_history is not dst.model.message_history
        # Modifying one should not affect the other
        dst.model.message_history.append({"role": "assistant", "content": "new msg"})
        assert len(src.model.message_history) == 2
        assert len(dst.model.message_history) == 2  # context + new msg

    def test_shared_reference_broken(self):
        """If dst already shares src's history by reference, injection must break the link."""
        src = _make_agent("A")
        dst = _make_agent("B")

        shared = _make_history([("user", "shared msg")])
        src.model.message_history = shared
        dst.model.message_history = shared  # same reference

        assert src.model.message_history is dst.model.message_history

        _inject_handoff_context(src, dst)

        # Must have broken the shared reference even if no briefing was produced
        # (source has only user messages → no assistant conclusion → no sections)
        assert src.model.message_history is not dst.model.message_history

    def test_empty_source_history(self):
        """No injection when source has no history."""
        src = _make_agent("A")
        dst = _make_agent("B")

        src.model.message_history = []

        _inject_handoff_context(src, dst)

        assert len(dst.model.message_history) == 0

    def test_commands_limit(self):
        """Only the last _MAX_COMMANDS_IN_BRIEFING commands are included."""
        src = _make_agent("A")
        dst = _make_agent("B")

        # Create 20 tool call messages
        history = []
        for i in range(20):
            history.append({"role": "assistant", "content": None, "tool_calls": [
                {"id": f"tc{i}", "type": "function", "function": {
                    "name": "generic_linux_command",
                    "arguments": f'{{"command": "cmd-{i}"}}'
                }}
            ]})
            history.append({"role": "tool", "tool_call_id": f"tc{i}", "content": f"output-{i}"})
        src.model.message_history = history

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        # Should contain last _MAX_COMMANDS_IN_BRIEFING commands
        assert "cmd-19" in ctx
        # Should NOT contain early commands (only last 15 kept)
        assert "cmd-0" not in ctx

    def test_conclusion_truncation(self):
        """Long assistant conclusions are truncated to _HANDOFF_MSG_TRUNCATE."""
        src = _make_agent("A")
        dst = _make_agent("B")

        long_content = "A" * 1000
        src.model.message_history = _make_history([
            ("assistant", long_content),
        ])

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        # Conclusion should be truncated
        assert "..." in ctx
        # The conclusion section should not contain the full 1000 chars
        assert "A" * 1000 not in ctx

    def test_tool_messages_included(self):
        """Tool results are included in Key Tool Outputs section."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {"name": "generic_linux_command", "arguments": '{"command": "nmap 10.0.0.1"}'}}
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": "22/tcp open ssh\n80/tcp open http"},
        ]

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        assert "## Key Tool Outputs" in ctx
        assert "22/tcp open ssh" in ctx

    def test_multiple_injections_accumulate(self):
        """Multiple handoffs to the same agent should accumulate context."""
        orch = _make_agent("Orch")
        recon = _make_agent("Recon")
        exploit = _make_agent("Exploit")

        recon.model.message_history = _make_history([
            ("assistant", "Found Apache 2.4.49"),
        ])
        exploit.model.message_history = _make_history([
            ("assistant", "CVE-2021-41773 exploited successfully"),
        ])

        _inject_handoff_context(recon, orch)
        _inject_handoff_context(exploit, orch)

        assert len(orch.model.message_history) == 2
        assert "[Handoff from Recon]" in orch.model.message_history[0]["content"]
        assert "[Handoff from Exploit]" in orch.model.message_history[1]["content"]

    def test_preserves_existing_dst_history(self):
        """Injection appends to existing destination history, not replaces."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        dst.model.message_history = _make_history([
            ("user", "Hack 10.0.0.1"),
            ("assistant", "I'll start with reconnaissance"),
        ])
        src.model.message_history = _make_history([
            ("assistant", "Ports: 22, 80, 443"),
        ])

        _inject_handoff_context(src, dst)

        assert len(dst.model.message_history) == 3
        assert dst.model.message_history[0]["content"] == "Hack 10.0.0.1"
        assert "[Handoff from Recon]" in dst.model.message_history[2]["content"]

    def test_empty_content_skipped(self):
        """Messages with empty content produce a conclusion only from the non-empty one."""
        src = _make_agent("A")
        dst = _make_agent("B")

        src.model.message_history = [
            {"role": "assistant", "content": ""},
            {"role": "assistant", "content": None},
            {"role": "assistant", "content": "Real content"},
        ]

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        assert "Real content" in ctx
        assert "## Agent Conclusion" in ctx


# ── Generated items filtering tests ─────────────────────────────────


class TestGeneratedItemsFiltering:
    """Test offset-based filtering: only NEW items from the current agent are included."""

    def _make_run_item(self, agent_name: str):
        """Create a minimal mock RunItem with agent.name."""
        item = MagicMock()
        item.agent = MagicMock()
        item.agent.name = agent_name
        item.to_input_item.return_value = {"type": "message", "agent": agent_name}
        return item

    def _simulate_filtering(self, agent, generated_items):
        """Simulate the offset-based filtering logic from _run_single_turn."""
        if getattr(agent, 'isolated_context', False) and hasattr(agent.model, 'message_history') and agent.model.message_history:
            offset = getattr(agent, '_isolated_items_offset', 0)
            filtered = []
            for item in generated_items[offset:]:
                if item.agent.name == agent.name:
                    filtered.append(item.to_input_item())
            agent._isolated_items_offset = len(generated_items)
            return filtered
        else:
            return [item.to_input_item() for item in generated_items]

    def test_first_turn_after_handoff_filters_other_agents(self):
        """Turn 1: offset=0, items from other agents are filtered out."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]

        items = [
            self._make_run_item("Orchestrator"),
            self._make_run_item("Orchestrator"),
            self._make_run_item("Orchestrator"),
        ]

        filtered = self._simulate_filtering(agent, items)
        assert len(filtered) == 0
        assert agent._isolated_items_offset == 3

    def test_second_turn_includes_own_new_items(self):
        """Turn 2: offset filters old items, includes only new items from this agent."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]

        # Simulate turn 1 items (from orchestrator)
        items_turn1 = [
            self._make_run_item("Orchestrator"),
            self._make_run_item("Orchestrator"),
        ]
        self._simulate_filtering(agent, items_turn1)
        assert agent._isolated_items_offset == 2

        # Simulate turn 2: new items added (agent's own tool call + result)
        items_turn2 = items_turn1 + [
            self._make_run_item("Recon"),  # assistant msg with tool_call
            self._make_run_item("Recon"),  # tool result
        ]
        filtered = self._simulate_filtering(agent, items_turn2)
        assert len(filtered) == 2
        assert agent._isolated_items_offset == 4

    def test_third_turn_only_newest_items(self):
        """Turn 3: only items after turn 2's offset, from this agent."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]

        all_items = [
            self._make_run_item("Orchestrator"),  # 0: from handoff
            self._make_run_item("Recon"),          # 1: turn 1 assistant
            self._make_run_item("Recon"),          # 2: turn 1 tool result
        ]
        # Simulate turns 1 and 2 already processed
        agent._isolated_items_offset = 3

        # Turn 3: new items added
        all_items.extend([
            self._make_run_item("Recon"),  # 3: turn 2 assistant
            self._make_run_item("Recon"),  # 4: turn 2 tool result
        ])
        filtered = self._simulate_filtering(agent, all_items)
        assert len(filtered) == 2
        assert agent._isolated_items_offset == 5

    def test_mixed_agents_only_own_included(self):
        """Items from other agents in the same slice are excluded."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]
        agent._isolated_items_offset = 2

        all_items = [
            self._make_run_item("Orchestrator"),  # 0: old
            self._make_run_item("Orchestrator"),  # 1: old
            self._make_run_item("Exploitation"),  # 2: new but wrong agent
            self._make_run_item("Recon"),          # 3: new, correct agent
            self._make_run_item("Exploitation"),  # 4: new but wrong agent
        ]
        filtered = self._simulate_filtering(agent, all_items)
        assert len(filtered) == 1
        assert filtered[0]["agent"] == "Recon"
        assert agent._isolated_items_offset == 5

    def test_no_filter_when_not_isolated(self):
        """Without isolated_context, all items should be included (no offset logic)."""
        agent = Agent(name="Recon", instructions="test", isolated_context=False)

        items = [
            self._make_run_item("Orchestrator"),
            self._make_run_item("Recon"),
            self._make_run_item("Exploitation"),
        ]

        if getattr(agent, 'isolated_context', False) and hasattr(agent.model, 'message_history') and getattr(agent.model, 'message_history', None):
            filtered = []
        else:
            filtered = [item.to_input_item() for item in items]

        assert len(filtered) == 3

    def test_includes_items_when_isolated_but_no_history(self):
        """With isolated_context but empty history (first turn), all items included."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = []  # empty = first turn

        items = [self._make_run_item("Recon")]

        filtered = self._simulate_filtering(agent, items)
        # No history → falls through to else branch, includes all
        assert len(filtered) == 1

    def test_empty_items_no_error(self):
        """Empty generated_items should not cause errors."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]

        filtered = self._simulate_filtering(agent, [])
        assert len(filtered) == 0
        assert agent._isolated_items_offset == 0


# ── Objective & user-instruction extraction tests ───────────────────


class TestBriefingObjectiveFiltering:
    def test_briefing_objective_skips_warning_messages(self):
        """Nudge warnings injected as role=user must NOT be extracted as objective."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "Scan 10.0.0.1"},
            {"role": "assistant", "content": "Scanning..."},
            {"role": "user", "content": "WARNING: You have executed very similar commands 3 times consecutively."},
            {"role": "assistant", "content": "OK, switching approach."},
        ]

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        assert "## Objective" in ctx
        assert "Scan 10.0.0.1" in ctx
        # The WARNING must NOT appear as the objective
        assert "WARNING: You have executed" not in ctx.split("## Objective")[1].split("##")[0]

    def test_briefing_propagates_subsequent_user_instructions(self):
        """User messages after the objective should appear as User Instructions in briefing."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "Scan 10.0.0.1"},
            {"role": "assistant", "content": "Scanning..."},
            {"role": "user", "content": "Focus on SQL injection vulnerabilities"},
            {"role": "assistant", "content": "Will focus on SQLi."},
        ]

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        assert "## Objective" in ctx
        assert "Scan 10.0.0.1" in ctx
        assert "## User Instructions (HIGH PRIORITY)" in ctx
        assert "Focus on SQL injection vulnerabilities" in ctx

    def test_briefing_skips_auto_continue_messages(self):
        """Auto-continue messages should not be extracted as user instructions."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "Scan 10.0.0.1"},
            {"role": "assistant", "content": "Scanning..."},
            {"role": "user", "content": "Continue working on the task based on your previous findings."},
            {"role": "assistant", "content": "Continuing..."},
            {"role": "user", "content": "Continue with your task based on the context provided."},
            {"role": "assistant", "content": "Still working."},
        ]

        _inject_handoff_context(src, dst)

        ctx = dst.model.message_history[0]["content"]
        # Should NOT have User Instructions section (only auto-continue messages after objective)
        assert "## User Instructions" not in ctx

    def test_briefing_no_duplicate_user_instructions_on_circular_handoff(self):
        """In A→B→A→C, instructions from before B's briefing must not be re-extracted."""
        agent_a = _make_agent("AgentA")
        agent_b = _make_agent("AgentB")
        agent_c = _make_agent("AgentC")

        # Step 1: User gives objective and instruction to A
        agent_a.model.message_history = [
            {"role": "user", "content": "Hack 10.0.0.1"},
            {"role": "assistant", "content": "Starting..."},
            {"role": "user", "content": "Use SQL injection"},
            {"role": "assistant", "content": "Will try SQLi."},
        ]

        # Step 2: A → B (B gets briefing with the instruction)
        _inject_handoff_context(agent_a, agent_b)
        ctx_b = agent_b.model.message_history[0]["content"]
        assert "Use SQL injection" in ctx_b  # instruction propagated ✓

        # Step 3: B → A (A receives briefing from B)
        agent_b.model.message_history.append(
            {"role": "assistant", "content": "SQLi failed, trying other approach."}
        )
        _inject_handoff_context(agent_b, agent_a)
        # A now has: original messages + briefing from B
        assert any(
            "[Handoff from AgentB]" in str(m.get("content", ""))
            for m in agent_a.model.message_history
        )

        # Step 4: A → C — "Use SQL injection" should NOT be re-extracted
        # because it came BEFORE the briefing from B
        _inject_handoff_context(agent_a, agent_c)
        ctx_c = agent_c.model.message_history[0]["content"]

        # The old instruction should not appear in User Instructions
        if "## User Instructions" in ctx_c:
            instructions_section = ctx_c.split("## User Instructions")[1].split("##")[0]
            assert "Use SQL injection" not in instructions_section

        # Step 5: Now add a NEW instruction after the briefing
        agent_a.model.message_history.append(
            {"role": "user", "content": "Try privilege escalation instead"}
        )
        agent_a.model.message_history.append(
            {"role": "assistant", "content": "OK, trying privesc."}
        )

        agent_d = _make_agent("AgentD")
        _inject_handoff_context(agent_a, agent_d)
        ctx_d = agent_d.model.message_history[0]["content"]
        assert "## User Instructions (HIGH PRIORITY)" in ctx_d
        assert "Try privilege escalation instead" in ctx_d


# ── Offset & round-trip tests (continuation of TestGeneratedItemsFiltering) ──


class TestOffsetAndRoundTrip(TestGeneratedItemsFiltering):
    """Tests that depend on _make_run_item and _simulate_filtering from TestGeneratedItemsFiltering."""

    def test_offset_set_on_handoff(self):
        """_inject_handoff_context sets _isolated_items_offset to current_items_len."""
        src = _make_agent("Orchestrator")
        dst = _make_agent("Recon")

        src.model.message_history = _make_history([("assistant", "Go scan")])
        dst._isolated_items_offset = 42  # leftover from previous run

        _inject_handoff_context(src, dst, current_items_len=100)

        assert hasattr(dst, '_isolated_items_offset')
        assert dst._isolated_items_offset == 100

    def test_offset_defaults_to_zero_when_no_items_len(self):
        """Without current_items_len, offset defaults to 0."""
        src = _make_agent("Orchestrator")
        dst = _make_agent("Recon")

        src.model.message_history = _make_history([("assistant", "Go scan")])
        dst._isolated_items_offset = 42

        _inject_handoff_context(src, dst)

        assert dst._isolated_items_offset == 0

    def test_round_trip_no_duplication(self):
        """A→B→A round-trip must not duplicate items from A's first run."""
        orch = _make_agent("Orchestrator")
        recon = _make_agent("Recon")
        orch.model.message_history = _make_history([
            ("user", "Hack target"),
            ("assistant", "Delegating to Recon"),
        ])

        items = []

        # Orch runs first, produces 5 items
        items.extend([self._make_run_item("Orchestrator") for _ in range(5)])
        self._simulate_filtering(orch, items)
        assert orch._isolated_items_offset == 5

        # Handoff Orch → Recon with current generated_items length = 5
        _inject_handoff_context(orch, recon, current_items_len=5)
        assert recon._isolated_items_offset == 5

        # Recon runs and adds 3 items
        items.extend([self._make_run_item("Recon") for _ in range(3)])
        filtered = self._simulate_filtering(recon, items)
        assert len(filtered) == 3  # only Recon's new items
        assert recon._isolated_items_offset == 8

        # Handoff Recon → Orch with current generated_items length = 8
        _inject_handoff_context(recon, orch, current_items_len=8)
        assert orch._isolated_items_offset == 8

        # Orch runs again — should see ZERO items from itself
        # (its items are at indices 0-4, all before offset 8)
        filtered = self._simulate_filtering(orch, items)
        assert len(filtered) == 0  # no duplication
        assert orch._isolated_items_offset == 8

    def test_multi_hop_no_duplication(self):
        """A→B→C→A multi-hop must not duplicate items."""
        a = _make_agent("A")
        b = _make_agent("B")
        c = _make_agent("C")
        a.model.message_history = _make_history([("user", "start")])
        b.model.message_history = []
        c.model.message_history = []

        items = []

        # A runs first, produces 2 items
        items.extend([self._make_run_item("A") for _ in range(2)])
        self._simulate_filtering(a, items)
        assert a._isolated_items_offset == 2

        # Handoff A→B
        _inject_handoff_context(a, b, current_items_len=2)
        b.model.message_history = [{"role": "user", "content": "briefing from A"}]
        assert b._isolated_items_offset == 2

        # B produces 3 items
        items.extend([self._make_run_item("B") for _ in range(3)])
        self._simulate_filtering(b, items)
        assert b._isolated_items_offset == 5

        # Handoff B→C
        _inject_handoff_context(b, c, current_items_len=5)
        c.model.message_history = [{"role": "user", "content": "briefing from B"}]
        assert c._isolated_items_offset == 5

        # C produces 2 items
        items.extend([self._make_run_item("C") for _ in range(2)])
        self._simulate_filtering(c, items)
        assert c._isolated_items_offset == 7

        # Handoff C→A
        _inject_handoff_context(c, a, current_items_len=7)
        assert a._isolated_items_offset == 7

        # A runs again — its items are at indices 0-1, before offset 7
        filtered = self._simulate_filtering(a, items)
        assert len(filtered) == 0  # no duplication
        assert a._isolated_items_offset == 7

    def test_offset_grows_monotonically(self):
        """Offset always equals len(generated_items) after each turn."""
        agent = _make_agent("Recon", isolated=True)
        agent.model.message_history = [{"role": "user", "content": "briefing"}]

        items = []
        for turn in range(5):
            items.append(self._make_run_item("Recon"))
            self._simulate_filtering(agent, items)
            assert agent._isolated_items_offset == len(items)


# ── Redteam orchestrated pattern tests ───────────────────────────────


class TestRedteamOrchestratedIsolation:
    def test_all_agents_have_isolated_context(self):
        """All 6 agents in redteam_orchestrated must have isolated_context=True."""
        from cai.agents.patterns.redteam_orchestrated import (
            _orchestrator, _recon, _strategy, _exploitation, _privesc, _report,
        )
        for agent in [_orchestrator, _recon, _strategy, _exploitation, _privesc, _report]:
            assert agent.isolated_context is True, f"{agent.name} missing isolated_context"

    def test_all_agents_have_lock_model(self):
        """All 6 agents must also have _lock_model=True (regression check)."""
        from cai.agents.patterns.redteam_orchestrated import (
            _orchestrator, _recon, _strategy, _exploitation, _privesc, _report,
        )
        for agent in [_orchestrator, _recon, _strategy, _exploitation, _privesc, _report]:
            assert agent._lock_model is True, f"{agent.name} missing _lock_model"


# ── End-to-end handoff simulation ────────────────────────────────────


class TestHandoffSimulation:
    """Simulate a full Orch → Recon → Orch handoff cycle with isolated context."""

    def test_full_handoff_cycle(self):
        """Simulate: Orch sends to Recon, Recon works, Recon returns to Orch."""
        orch = _make_agent("Orchestrator")
        recon = _make_agent("Recon")

        # Step 1: Orch has initial user request and its own response
        orch.model.message_history = _make_history([
            ("user", "Perform a penetration test on 10.0.0.1"),
            ("assistant", "I'll delegate reconnaissance to the Recon agent."),
        ])

        # Step 2: Handoff Orch → Recon (inject context)
        _inject_handoff_context(orch, recon)

        # Recon should have the structured briefing with the conclusion
        assert len(recon.model.message_history) == 1
        briefing = recon.model.message_history[0]["content"]
        assert "[Handoff from Orchestrator]" in briefing
        # Structured briefing contains agent conclusion, not raw user messages
        assert "delegate reconnaissance" in briefing

        # Step 3: Recon does its work
        recon.model.message_history.extend(_make_history([
            ("assistant", "Running nmap -sV -sC 10.0.0.1"),
            ("tool", "22/tcp open ssh OpenSSH 8.2\n80/tcp open http Apache 2.4.49\n443/tcp open ssl"),
            ("assistant", "Found 3 open ports. Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773)."),
        ]))

        # Step 4: Handoff Recon → Orch (inject context back)
        _inject_handoff_context(recon, orch)

        # Orch should have its original history + Recon's report
        assert len(orch.model.message_history) == 3
        assert orch.model.message_history[0]["content"] == "Perform a penetration test on 10.0.0.1"
        assert "[Handoff from Recon]" in orch.model.message_history[2]["content"]
        assert "CVE-2021-41773" in orch.model.message_history[2]["content"]

        # Histories remain independent
        assert orch.model.message_history is not recon.model.message_history

    def test_multi_specialist_cycle(self):
        """Simulate: Orch → Recon → Orch → Exploit → Orch."""
        orch = _make_agent("Orchestrator")
        recon = _make_agent("Recon")
        exploit = _make_agent("Exploit")

        # Initial — orch only has user msg (no assistant = no briefing content)
        orch.model.message_history = _make_history([
            ("user", "Hack 10.0.0.1"),
        ])

        # Orch → Recon: no assistant msg in orch, but user objective → briefing with ## Objective
        _inject_handoff_context(orch, recon)
        recon.model.message_history.extend(_make_history([
            ("assistant", "Port 80 open, Apache 2.4.49"),
        ]))

        # Recon → Orch: recon has assistant conclusion → briefing injected
        _inject_handoff_context(recon, orch)
        orch.model.message_history.extend(_make_history([
            ("assistant", "Recon found Apache vuln, delegating to Exploit"),
        ]))

        # Orch → Exploit: orch has conclusion → briefing injected
        _inject_handoff_context(orch, exploit)
        exploit.model.message_history.extend(_make_history([
            ("assistant", "Exploiting CVE-2021-41773... got shell!"),
        ]))

        # Exploit → Orch
        _inject_handoff_context(exploit, orch)

        # Verify: Orch has accumulated context from both specialists
        # user + recon_briefing + orch_resp + exploit_briefing = 4
        assert len(orch.model.message_history) == 4
        contents = " ".join(m["content"] for m in orch.model.message_history)
        assert "Hack 10.0.0.1" in contents
        assert "Apache 2.4.49" in contents
        assert "got shell" in contents

        # Verify: each specialist has only its own context
        # Recon: briefing from orch (with ## Objective) + 1 response = 2
        assert len(recon.model.message_history) == 2
        assert "## Objective" in recon.model.message_history[0]["content"]
        # Exploit: briefing from orch + 1 response = 2
        assert len(exploit.model.message_history) == 2

        # Verify: all histories are independent
        histories = [orch.model.message_history, recon.model.message_history, exploit.model.message_history]
        for i in range(len(histories)):
            for j in range(i + 1, len(histories)):
                assert histories[i] is not histories[j], f"History {i} and {j} share reference"


class TestIsolatedItemsOffsetDataclass:
    """_isolated_items_offset must be a declared dataclass field."""

    def test_offset_is_dataclass_field(self):
        """_isolated_items_offset should be in Agent's dataclass fields."""
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(Agent)}
        assert "_isolated_items_offset" in field_names

    def test_offset_survives_dataclass_replace(self):
        """Cloning an agent via dataclasses.replace must preserve the offset."""
        import dataclasses
        agent = Agent(name="test", isolated_context=True)
        agent._isolated_items_offset = 42
        cloned = dataclasses.replace(agent)
        assert cloned._isolated_items_offset == 42

    def test_offset_default_is_zero(self):
        agent = Agent(name="test")
        assert agent._isolated_items_offset == 0


class TestStructuredBriefing:
    """Tests for the structured briefing format."""

    def test_briefing_has_commands_section(self):
        """Briefing should list commands executed by source agent."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {
                    "name": "generic_linux_command",
                    "arguments": '{"command": "nmap -sV 10.0.0.1"}'
                }}
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": "22/tcp open ssh"},
            {"role": "assistant", "content": "Scan complete"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Commands Executed" in ctx
        assert "nmap -sV 10.0.0.1" in ctx

    def test_briefing_has_tool_outputs_section(self):
        """Briefing should include tool outputs in Key Tool Outputs section."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {
                    "name": "generic_linux_command",
                    "arguments": '{"command": "nmap 10.0.0.1"}'
                }}
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": "80/tcp open http Apache 2.4.49"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Key Tool Outputs" in ctx
        assert "Apache 2.4.49" in ctx

    def test_briefing_has_conclusion_section(self):
        """Last assistant message becomes the Agent Conclusion."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = [
            {"role": "assistant", "content": "First thought"},
            {"role": "assistant", "content": "Final conclusion: target is vulnerable"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Agent Conclusion" in ctx
        assert "Final conclusion: target is vulnerable" in ctx
        # First thought should NOT be in conclusion (only last assistant msg)
        assert "First thought" not in ctx

    def test_briefing_excludes_findings_tools(self):
        """write_key_findings and read_key_findings should not appear in commands/outputs."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {
                    "name": "generic_linux_command",
                    "arguments": '{"command": "nmap 10.0.0.1"}'
                }},
                {"id": "tc2", "type": "function", "function": {
                    "name": "write_key_findings",
                    "arguments": '{"findings": "Port 80 open"}'
                }},
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": "80/tcp open http"},
            {"role": "tool", "tool_call_id": "tc2", "content": "Successfully wrote findings"},
            {"role": "assistant", "content": "Done scanning"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        # nmap should be in commands, write_key_findings should NOT
        assert "nmap 10.0.0.1" in ctx
        assert "write_key_findings" not in ctx
        assert "Successfully wrote findings" not in ctx

    def test_briefing_truncates_long_tool_output(self):
        """Tool outputs longer than _TOOL_OUTPUT_TRUNCATE should be truncated."""
        src = _make_agent("A")
        dst = _make_agent("B")

        long_output = "X" * 5000
        src.model.message_history = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {
                    "name": "generic_linux_command",
                    "arguments": '{"command": "cat big_file"}'
                }}
            ]},
            {"role": "tool", "tool_call_id": "tc1", "content": long_output},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert f"[5000 chars total]" in ctx
        assert long_output not in ctx

    def test_previous_briefing_from_same_source_replaced(self):
        """Second handoff from same agent replaces previous briefing."""
        src = _make_agent("Recon")
        dst = _make_agent("Orch")

        src.model.message_history = _make_history([("assistant", "First scan")])
        _inject_handoff_context(src, dst)

        src.model.message_history = _make_history([("assistant", "Second scan")])
        _inject_handoff_context(src, dst)

        # Should have exactly 1 briefing from Recon
        briefings = [m for m in dst.model.message_history
                     if "[Handoff from Recon]" in m.get("content", "")]
        assert len(briefings) == 1
        assert "Second scan" in briefings[0]["content"]

    def test_briefings_from_different_sources_coexist(self):
        """Briefings from A and C should both exist in B's history."""
        a = _make_agent("A")
        c = _make_agent("C")
        b = _make_agent("B")

        a.model.message_history = _make_history([("assistant", "From A")])
        c.model.message_history = _make_history([("assistant", "From C")])

        _inject_handoff_context(a, b)
        _inject_handoff_context(c, b)

        assert len(b.model.message_history) == 2
        assert "[Handoff from A]" in b.model.message_history[0]["content"]
        assert "[Handoff from C]" in b.model.message_history[1]["content"]

    def test_max_briefings_limit(self):
        """At most _MAX_BRIEFINGS_PER_AGENT briefings from different sources."""
        dst = _make_agent("Orch")

        for i in range(5):
            src = _make_agent(f"Agent{i}")
            src.model.message_history = _make_history([("assistant", f"From agent {i}")])
            _inject_handoff_context(src, dst)

        briefings = [m for m in dst.model.message_history
                     if m.get("content", "").startswith("[Handoff from ")]
        assert len(briefings) == 3, f"Expected 3 briefings, got {len(briefings)}"  # _MAX_BRIEFINGS_PER_AGENT

    def test_agent_with_only_text_no_tools(self):
        """Agent that only produced text should have conclusion only."""
        src = _make_agent("Strategy")
        dst = _make_agent("Orch")

        src.model.message_history = _make_history([
            ("assistant", "Plan: attack port 80 first"),
        ])

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Agent Conclusion" in ctx
        assert "## Commands Executed" not in ctx
        assert "## Key Tool Outputs" not in ctx

    def test_includes_state_txt_when_present(self, tmp_path, monkeypatch):
        """Briefing should include state.txt content in Current Findings section."""
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        (tmp_path / "state.txt").write_text("Port 80: Apache 2.4.49\nCredentials: admin:pass\n")

        src = _make_agent("Recon")
        dst = _make_agent("Orch")
        src.model.message_history = _make_history([("assistant", "Done")])

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Current Findings (state.txt)" in ctx
        assert "admin:pass" in ctx

    def test_no_findings_section_when_no_state_txt(self, tmp_path, monkeypatch):
        """No Current Findings section when state.txt doesn't exist."""
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        # No state.txt created

        src = _make_agent("Recon")
        dst = _make_agent("Orch")
        src.model.message_history = _make_history([("assistant", "Done")])

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Current Findings" not in ctx

    def test_briefing_has_objective_section(self):
        """User objective from source agent is included as first section."""
        src = _make_agent("Orchestrator")
        dst = _make_agent("Recon")

        src.model.message_history = [
            {"role": "user", "content": "Pentest the ip 172.17.0.2"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "tc1", "type": "function", "function": {
                    "name": "transfer_to_recon_agent",
                    "arguments": "{}"
                }}
            ]},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Objective" in ctx
        assert "172.17.0.2" in ctx
        # Objective should be the first section after the handoff header
        assert ctx.index("## Objective") < ctx.index("## Agent Conclusion") if "## Agent Conclusion" in ctx else True

    def test_briefing_objective_skips_continue_message(self):
        """The 'Continue with your task' message should NOT become the objective."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "Continue with your task based on the context provided."},
            {"role": "assistant", "content": "Done scanning"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        assert "## Objective" not in ctx

    def test_briefing_objective_skips_handoff_messages(self):
        """Briefing messages from other agents should NOT become the objective."""
        src = _make_agent("Recon")
        dst = _make_agent("Orchestrator")

        src.model.message_history = [
            {"role": "user", "content": "[Handoff from Red Team Orchestrator]\n\n## Objective\nPentest 10.0.0.1"},
            {"role": "user", "content": "Continue with your task based on the context provided."},
            {"role": "assistant", "content": "Scan complete"},
        ]

        _inject_handoff_context(src, dst)
        ctx = dst.model.message_history[0]["content"]

        # No objective section since all user messages are briefings or continue
        assert "## Objective" not in ctx

    def test_briefing_objective_no_duplication_on_re_handoff(self):
        """Second handoff from same source replaces briefing, no duplicate objectives."""
        src = _make_agent("Orchestrator")
        dst = _make_agent("Recon")

        src.model.message_history = [
            {"role": "user", "content": "Pentest the ip 172.17.0.2"},
            {"role": "assistant", "content": "Starting recon"},
        ]

        _inject_handoff_context(src, dst)
        _inject_handoff_context(src, dst)  # Second handoff

        # Should have exactly 1 briefing
        briefings = [m for m in dst.model.message_history
                     if "[Handoff from Orchestrator]" in m.get("content", "")]
        assert len(briefings) == 1
        # Objective appears once
        assert briefings[0]["content"].count("## Objective") == 1
