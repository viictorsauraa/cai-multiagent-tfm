"""
Tests for the Redteam Orchestrated Pattern.

Verifies that the hub-and-spoke agent topology works correctly:
- Orchestrator hands off to specialist agents
- Specialist agents hand back to orchestrator
- Multiple handoffs in sequence work (Orch → Recon → Orch → Exploit → Orch)
- Tools execute correctly alongside handoffs
- Agent identity (name, model) is preserved across handoffs
- _lock_model prevents model overwriting
"""

from __future__ import annotations

import pytest

from cai.sdk.agents import (
    Agent,
    Handoff,
    Runner,
    RunConfig,
    handoff,
    function_tool,
)
from cai.sdk.agents.items import RunItem, HandoffCallItem, HandoffOutputItem, ToolCallItem, ToolCallOutputItem, MessageOutputItem

from tests.fake_model import FakeModel
from tests.core.test_responses import (
    get_text_message,
    get_function_tool,
    get_function_tool_call,
    get_handoff_tool_call,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _print_separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _print_result(result):
    """Print a detailed trace of the RunResult."""
    print(f"\n  Final output: \"{result.final_output}\"")
    print(f"  Last agent:   {result.last_agent.name}")
    print(f"  Total turns:  {len(result.raw_responses)}")
    print(f"  Total items:  {len(result.new_items)}")
    print()

    turn = 0
    current_agent = "?"
    for i, item in enumerate(result.new_items):
        if isinstance(item, HandoffCallItem):
            target = item.raw_item.name if hasattr(item.raw_item, 'name') else "?"
            print(f"    [{i}] HANDOFF CALL  → {target}")
        elif isinstance(item, HandoffOutputItem):
            current_agent = item.raw_item.get("agent_name", "?") if isinstance(item.raw_item, dict) else "?"
            print(f"    [{i}] HANDOFF OUT   ✓ now running: {current_agent}")
            turn += 1
        elif isinstance(item, ToolCallItem):
            tool_name = item.raw_item.name if hasattr(item.raw_item, 'name') else "?"
            args = item.raw_item.arguments if hasattr(item.raw_item, 'arguments') else ""
            print(f"    [{i}] TOOL CALL     {tool_name}({args})")
        elif isinstance(item, ToolCallOutputItem):
            output = item.output
            if len(str(output)) > 60:
                output = str(output)[:60] + "..."
            print(f"    [{i}] TOOL OUTPUT   → {output}")
        elif isinstance(item, MessageOutputItem):
            text = ""
            if hasattr(item.raw_item, 'content'):
                for c in item.raw_item.content:
                    if hasattr(c, 'text'):
                        text = c.text
            if len(text) > 80:
                text = text[:80] + "..."
            print(f"    [{i}] MESSAGE       \"{text}\"")
        else:
            print(f"    [{i}] {type(item).__name__}: {item}")


def build_orchestrated_pattern():
    """
    Build a minimal version of the redteam orchestrated pattern
    using FakeModel instances (no real LLM calls).

    Returns the orchestrator agent and a dict of all agents with their models.
    """
    # Create independent FakeModel for each agent
    orch_model = FakeModel()
    recon_model = FakeModel()
    strategy_model = FakeModel()
    exploit_model = FakeModel()
    privesc_model = FakeModel()
    report_model = FakeModel()

    # Define tools similar to the real pattern
    think_tool = get_function_tool("think", "thought recorded")
    read_kf_tool = get_function_tool("read_key_findings", "no findings yet")
    write_kf_tool = get_function_tool("write_key_findings", "findings saved")
    linux_cmd_tool = get_function_tool("generic_linux_command", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http")

    # Create agents
    orchestrator = Agent(
        name="Red Team Orchestrator",
        model=orch_model,
        tools=[think_tool, read_kf_tool],
    )
    recon = Agent(
        name="Recon Agent",
        model=recon_model,
        tools=[linux_cmd_tool, write_kf_tool, read_kf_tool],
    )
    strategy = Agent(
        name="Strategy Agent",
        model=strategy_model,
        tools=[think_tool, write_kf_tool, read_kf_tool],
    )
    exploitation = Agent(
        name="Exploitation Agent",
        model=exploit_model,
        tools=[linux_cmd_tool, write_kf_tool, read_kf_tool],
    )
    privesc = Agent(
        name="PrivEsc Agent",
        model=privesc_model,
        tools=[linux_cmd_tool, write_kf_tool, read_kf_tool],
    )
    report = Agent(
        name="Report Agent",
        model=report_model,
        tools=[linux_cmd_tool, read_kf_tool],
    )

    # Lock models (like the real pattern does)
    for a in [orchestrator, recon, strategy, exploitation, privesc, report]:
        a._lock_model = True

    # Wire handoffs — hub-and-spoke
    orchestrator.handoffs = [
        handoff(agent=recon),
        handoff(agent=strategy),
        handoff(agent=exploitation),
        handoff(agent=privesc),
        handoff(agent=report),
    ]
    orch_handoff = handoff(agent=orchestrator)
    recon.handoffs = [orch_handoff]
    strategy.handoffs = [orch_handoff]
    exploitation.handoffs = [orch_handoff]
    privesc.handoffs = [orch_handoff]
    report.handoffs = [orch_handoff]

    agents = {
        "orchestrator": orchestrator,
        "recon": recon,
        "strategy": strategy,
        "exploitation": exploitation,
        "privesc": privesc,
        "report": report,
    }
    models = {
        "orchestrator": orch_model,
        "recon": recon_model,
        "strategy": strategy_model,
        "exploitation": exploit_model,
        "privesc": privesc_model,
        "report": report_model,
    }

    return orchestrator, agents, models


# ── Tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_handoff_orch_to_recon_and_back():
    """Orchestrator → Recon → Orchestrator → final text."""
    _print_separator("TEST: Single Handoff (Orch → Recon → Orch)")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup:")
    print("    Turn 1: Orchestrator calls think() + handoff → Recon")
    print("    Turn 2: Recon calls nmap + write_findings + handoff → Orch")
    print("    Turn 3: Orchestrator gives final text response")

    # Turn 1: Orchestrator thinks, then hands off to Recon
    models["orchestrator"].add_multiple_turn_outputs([
        [
            get_function_tool_call("think", '{"thought": "Start with recon"}'),
            get_handoff_tool_call(agents["recon"]),
        ],
    ])

    # Turn 2: Recon runs a command, writes findings, hands back to Orch
    models["recon"].add_multiple_turn_outputs([
        [
            get_function_tool_call("generic_linux_command", '{"command": "nmap -sV 172.17.0.2"}'),
            get_function_tool_call("write_key_findings", '{"findings": "SSH on 22, HTTP on 80"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Turn 3: Orchestrator gives final answer
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("Recon complete. Found SSH and HTTP services.")],
    ])

    result = await Runner.run(orch, input="Pentest 172.17.0.2")

    print("\n  Execution trace:")
    _print_result(result)

    assert result.final_output == "Recon complete. Found SSH and HTTP services."
    assert result.last_agent.name == "Red Team Orchestrator"
    assert len(result.raw_responses) == 3
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_multiple_handoffs_full_chain():
    """Orchestrator → Recon → Orch → Strategy → Orch → Exploit → Orch → final."""
    _print_separator("TEST: Full Chain (Orch → Recon → Orch → Strategy → Orch → Exploit → Orch)")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup:")
    print("    Turn 1: Orch → handoff Recon")
    print("    Turn 2: Recon: nmap + write_findings → handoff Orch")
    print("    Turn 3: Orch → handoff Strategy")
    print("    Turn 4: Strategy: think + write_findings → handoff Orch")
    print("    Turn 5: Orch → handoff Exploitation")
    print("    Turn 6: Exploitation: curl + write_findings → handoff Orch")
    print("    Turn 7: Orch → final text")

    # Turn 1: Orch → Recon
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["recon"])],
    ])

    # Turn 2: Recon scans, hands back
    models["recon"].add_multiple_turn_outputs([
        [
            get_function_tool_call("generic_linux_command", '{"command": "nmap 172.17.0.2"}'),
            get_function_tool_call("write_key_findings", '{"findings": "port 80 open"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Turn 3: Orch → Strategy
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["strategy"])],
    ])

    # Turn 4: Strategy analyzes, hands back
    models["strategy"].add_multiple_turn_outputs([
        [
            get_function_tool_call("think", '{"thought": "HTTP on 80 — try web exploits"}'),
            get_function_tool_call("write_key_findings", '{"findings": "attack plan: web app exploit"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Turn 5: Orch → Exploitation
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["exploitation"])],
    ])

    # Turn 6: Exploitation runs exploit, hands back
    models["exploitation"].add_multiple_turn_outputs([
        [
            get_function_tool_call("generic_linux_command", '{"command": "curl http://172.17.0.2/shell.php"}'),
            get_function_tool_call("write_key_findings", '{"findings": "shell obtained"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Turn 7: Orch final answer
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("Exploitation successful. Shell obtained via web vulnerability.")],
    ])

    result = await Runner.run(orch, input="Pentest 172.17.0.2")

    print("\n  Execution trace:")
    _print_result(result)

    assert result.final_output == "Exploitation successful. Shell obtained via web vulnerability."
    assert result.last_agent.name == "Red Team Orchestrator"
    assert len(result.raw_responses) == 7
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_handoff_to_all_specialists():
    """Orchestrator hands off to each specialist exactly once and returns."""
    _print_separator("TEST: All 5 Specialists (Orch → each specialist → Orch)")
    orch, agents, models = build_orchestrated_pattern()

    specialist_order = ["recon", "strategy", "exploitation", "privesc", "report"]

    print("\n  Setup:")
    for i, name in enumerate(specialist_order):
        t = i * 2 + 1
        print(f"    Turn {t}: Orch → handoff {name.title()}")
        print(f"    Turn {t+1}: {name.title()}: read_findings → handoff Orch")

    print(f"    Turn 11: Orch → final text")

    for i, spec_name in enumerate(specialist_order):
        # Orch → Specialist
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents[spec_name])],
        ])

        # Specialist does work, hands back
        models[spec_name].add_multiple_turn_outputs([
            [
                get_function_tool_call("read_key_findings", "{}"),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

    # Final Orch response
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("All phases complete. Pentest finished.")],
    ])

    result = await Runner.run(orch, input="Full pentest of 172.17.0.2")

    print("\n  Execution trace:")
    _print_result(result)

    assert result.final_output == "All phases complete. Pentest finished."
    assert result.last_agent.name == "Red Team Orchestrator"
    # 5 specialists * 2 turns (handoff + work) + 1 final = 11
    assert len(result.raw_responses) == 11
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_tools_execute_during_handoffs():
    """Verify that tool calls produce RunItems with correct outputs."""
    _print_separator("TEST: Tools Execute During Handoffs")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup:")
    print("    Turn 1: Orch: think() + handoff → Recon")
    print("    Turn 2: Recon: generic_linux_command() + handoff → Orch")
    print("    Turn 3: Orch → final text")

    # Orch uses think, then hands off
    models["orchestrator"].add_multiple_turn_outputs([
        [
            get_function_tool_call("think", '{"thought": "plan the attack"}'),
            get_handoff_tool_call(agents["recon"]),
        ],
    ])

    # Recon runs a command, hands back
    models["recon"].add_multiple_turn_outputs([
        [
            get_function_tool_call("generic_linux_command", '{"command": "nmap"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Orch final
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("Done")],
    ])

    result = await Runner.run(orch, input="test")

    print("\n  Execution trace:")
    _print_result(result)

    # Verify tool outputs exist in the generated items
    tool_output_items = [
        item for item in result.new_items
        if isinstance(item, ToolCallOutputItem)
    ]
    print(f"  Tool output items found: {len(tool_output_items)}")
    for item in tool_output_items:
        print(f"    → output: {item.output}")

    assert len(tool_output_items) >= 2, f"Expected at least 2 tool outputs, got {len(tool_output_items)}"
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_agent_identity_preserved_across_handoffs():
    """Each agent should maintain its own name when it runs."""
    _print_separator("TEST: Agent Identity Preserved Across Handoffs")
    orch, agents, models = build_orchestrated_pattern()

    agents_that_ran = []

    # Track which agent's model gets called
    original_get_response_orch = models["orchestrator"].get_response
    original_get_response_recon = models["recon"].get_response
    original_get_response_exploit = models["exploitation"].get_response

    async def track_orch(*args, **kwargs):
        agents_that_ran.append("orchestrator")
        return await original_get_response_orch(*args, **kwargs)

    async def track_recon(*args, **kwargs):
        agents_that_ran.append("recon")
        return await original_get_response_recon(*args, **kwargs)

    async def track_exploit(*args, **kwargs):
        agents_that_ran.append("exploitation")
        return await original_get_response_exploit(*args, **kwargs)

    models["orchestrator"].get_response = track_orch
    models["recon"].get_response = track_recon
    models["exploitation"].get_response = track_exploit

    print("\n  Setup: Orch → Recon → Orch → Exploit → Orch (tracking model calls)")

    # Orch → Recon → Orch → Exploit → Orch
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["recon"])],
    ])
    models["recon"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["orchestrator"])],
    ])
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["exploitation"])],
    ])
    models["exploitation"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["orchestrator"])],
    ])
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("finished")],
    ])

    result = await Runner.run(orch, input="go")

    print(f"\n  Expected execution order: orchestrator → recon → orchestrator → exploitation → orchestrator")
    print(f"  Actual execution order:   {' → '.join(agents_that_ran)}")

    assert agents_that_ran == ["orchestrator", "recon", "orchestrator", "exploitation", "orchestrator"]
    assert result.last_agent.name == "Red Team Orchestrator"
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_max_turns_limits_handoffs():
    """Runner should stop after max_turns even if agents keep handing off."""
    _print_separator("TEST: Max Turns Limits Infinite Handoff Loop")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup: Orch ↔ Recon infinite loop, max_turns=4")

    # Set up infinite loop: Orch → Recon → Orch → Recon → ...
    for _ in range(10):
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["orchestrator"])],
        ])

    from cai.sdk.agents import MaxTurnsExceeded
    try:
        await Runner.run(orch, input="loop", max_turns=4)
        print("  ✗ Should have raised MaxTurnsExceeded!")
        assert False
    except MaxTurnsExceeded:
        print("  MaxTurnsExceeded raised after 4 turns ✓")
    print("  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_lock_model_attribute_survives():
    """Agents with _lock_model=True should retain it after handoffs."""
    _print_separator("TEST: _lock_model Attribute Survives Handoffs")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup: Orch → Recon → Orch, checking _lock_model before and after")

    print(f"\n  Before run:")
    for name in ["orchestrator", "recon", "strategy", "exploitation", "privesc", "report"]:
        locked = getattr(agents[name], "_lock_model", False)
        print(f"    {name:20s} _lock_model={locked}")

    # Simple Orch → Recon → Orch
    models["orchestrator"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["recon"])],
    ])
    models["recon"].add_multiple_turn_outputs([
        [get_handoff_tool_call(agents["orchestrator"])],
    ])
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("done")],
    ])

    result = await Runner.run(orch, input="test")

    print(f"\n  After run:")
    for name in ["orchestrator", "recon", "strategy", "exploitation", "privesc", "report"]:
        locked = getattr(agents[name], "_lock_model", False)
        print(f"    {name:20s} _lock_model={locked}")

    # Verify _lock_model is still set on both agents
    assert getattr(agents["orchestrator"], "_lock_model", False) is True
    assert getattr(agents["recon"], "_lock_model", False) is True
    assert result.last_agent.name == "Red Team Orchestrator"
    print("\n  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_handoff_tool_names_are_correct():
    """Handoff tool names should match the expected transfer_to_* pattern."""
    _print_separator("TEST: Handoff Tool Names")
    orch, agents, _ = build_orchestrated_pattern()

    # Verify orchestrator's handoff tool names
    orch_handoff_names = {h.tool_name for h in orch.handoffs}
    expected = {
        Handoff.default_tool_name(agents["recon"]),
        Handoff.default_tool_name(agents["strategy"]),
        Handoff.default_tool_name(agents["exploitation"]),
        Handoff.default_tool_name(agents["privesc"]),
        Handoff.default_tool_name(agents["report"]),
    }

    print(f"\n  Orchestrator handoff tools:")
    for name in sorted(orch_handoff_names):
        status = "✓" if name in expected else "✗"
        print(f"    {status} {name}")

    assert orch_handoff_names == expected

    # Verify each specialist hands back to orchestrator
    orch_tool = Handoff.default_tool_name(agents["orchestrator"])
    print(f"\n  Specialist → Orchestrator handoff tool:")
    for name in ["recon", "strategy", "exploitation", "privesc", "report"]:
        agent = agents[name]
        actual = agent.handoffs[0].tool_name
        status = "✓" if actual == orch_tool else "✗"
        print(f"    {status} {name:20s} → {actual}")
        assert len(agent.handoffs) == 1
        assert actual == orch_tool

    print("\n  ✓ All assertions passed")


@pytest.mark.asyncio
async def test_tool_and_handoff_in_same_response():
    """A single model response can contain both tool calls and a handoff."""
    _print_separator("TEST: Tool Calls + Handoff in Same Response")
    orch, agents, models = build_orchestrated_pattern()

    print("\n  Setup:")
    print("    Turn 1: Orch calls think() + read_key_findings() + handoff → Recon (all in 1 response)")
    print("    Turn 2: Recon calls nmap + write_findings + handoff → Orch (all in 1 response)")
    print("    Turn 3: Orch → final text")

    # Orch calls think AND hands off in the same response
    models["orchestrator"].add_multiple_turn_outputs([
        [
            get_function_tool_call("think", '{"thought": "recon first"}'),
            get_function_tool_call("read_key_findings", "{}"),
            get_handoff_tool_call(agents["recon"]),
        ],
    ])

    # Recon runs command + writes findings + hands back in one response
    models["recon"].add_multiple_turn_outputs([
        [
            get_function_tool_call("generic_linux_command", '{"command": "nmap -p- 172.17.0.2"}'),
            get_function_tool_call("write_key_findings", '{"findings": "22,80 open"}'),
            get_handoff_tool_call(agents["orchestrator"]),
        ],
    ])

    # Final
    models["orchestrator"].add_multiple_turn_outputs([
        [get_text_message("Recon done: ports 22 and 80.")],
    ])

    result = await Runner.run(orch, input="scan target")

    print("\n  Execution trace:")
    _print_result(result)

    assert result.final_output == "Recon done: ports 22 and 80."
    assert len(result.raw_responses) == 3
    print("  ✓ All assertions passed")
