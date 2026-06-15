"""
Multi-Model Swarm Pattern for Red Team Operations

Each agent uses a different model size suited to its role:
- Strategist (thought_agent): large model for planning and reasoning
- Executor (redteam_agent): capable model for tool calling and exploitation
- Recon (one_tool_agent): lighter model for simple command execution

Agents hand off to each other based on the task at hand.
The _lock_model attribute prevents update_agent_models_recursively
from overwriting per-agent model assignments.
"""
import os
from cai.agents.red_teamer import redteam_agent
from cai.agents.thought import thought_agent
from cai.agents.one_tool import one_tool_agent
from cai.sdk.agents import handoff, OpenAIChatCompletionsModel
from openai import AsyncOpenAI

# ---------------------------------------------------------------------------
# Clone agents so we don't mutate the originals
# ---------------------------------------------------------------------------
_strategist = thought_agent.clone()
_executor = redteam_agent.clone()
_recon = one_tool_agent.clone()

# ---------------------------------------------------------------------------
# Assign a DIFFERENT model to each agent and lock it
# ---------------------------------------------------------------------------
_strategist.name = "Strategist (thinking)"
_strategist.model = OpenAIChatCompletionsModel(
    model=os.getenv("CAI_STRATEGIST_MODEL", "qwen2.5:32b"),
    openai_client=AsyncOpenAI(),
    agent_name=_strategist.name,
)
_strategist._lock_model = True

_executor.name = "Executor (red team)"
_executor.model = OpenAIChatCompletionsModel(
    model=os.getenv("CAI_EXECUTOR_MODEL", "qwen2.5:7b"),
    openai_client=AsyncOpenAI(),
    agent_name=_executor.name,
)
_executor._lock_model = True

_recon.name = "Recon (one tool)"
_recon.model = OpenAIChatCompletionsModel(
    model=os.getenv("CAI_RECON_MODEL", "qwen3:8b"),
    openai_client=AsyncOpenAI(),
    agent_name=_recon.name,
)
_recon._lock_model = True

# ---------------------------------------------------------------------------
# Wire handoffs
# ---------------------------------------------------------------------------
_strategist.handoffs = [
    handoff(
        agent=_executor,
        tool_description_override=(
            "Hand off to the Executor for running security tools, "
            "exploitation, and active assessment tasks"
        ),
    ),
    handoff(
        agent=_recon,
        tool_description_override=(
            "Hand off to Recon for quick reconnaissance commands "
            "(nmap, curl, etc.)"
        ),
    ),
]

_executor.handoffs = [
    handoff(
        agent=_strategist,
        tool_description_override=(
            "Hand off to the Strategist when you need to plan the "
            "next steps or analyze findings"
        ),
    ),
]

_recon.handoffs = [
    handoff(
        agent=_strategist,
        tool_description_override=(
            "Hand off to the Strategist once reconnaissance is done "
            "so it can plan next steps"
        ),
    ),
]

# ---------------------------------------------------------------------------
# Entry point — the Strategist starts the workflow
# ---------------------------------------------------------------------------
multi_model_swarm_pattern = _strategist
multi_model_swarm_pattern.pattern = "swarm"

# Mark all agents in the swarm
_executor.pattern = "swarm"
_recon.pattern = "swarm"
