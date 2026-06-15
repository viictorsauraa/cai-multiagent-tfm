"""
Orchestrated Red Team Swarm Pattern

6-agent structure coordinated by a central Orchestrator (hub-and-spoke):

  Orchestrator (hub)
  ├── Recon Agent        — discovery and enumeration
  ├── Strategy Agent     — analysis and attack planning
  ├── Exploitation Agent — vulnerability exploitation
  ├── PrivEsc Agent      — privilege escalation
  └── Report Agent       — evidence collection and reporting

Each agent is defined in its own module under cai/agents/ with a dedicated
system prompt loaded via create_system_prompt_renderer(). The pattern file
only clones, assigns per-agent models, and wires handoffs.

Per-agent models can be overridden with environment variables:
  CAI_ORCH_MODEL, CAI_RECON_MODEL, CAI_STRATEGY_MODEL,
  CAI_EXPLOIT_MODEL, CAI_PRIVESC_MODEL, CAI_REPORT_MODEL
"""

import logging
import os
import urllib.request
import json

from openai import AsyncOpenAI
from cai.sdk.agents import handoff, OpenAIChatCompletionsModel

from cai.agents.orchestrator import orchestrator_agent
from cai.agents.recon import recon_agent
from cai.agents.strategy import strategy_agent
from cai.agents.exploitation import exploitation_agent
from cai.agents.privesc import privesc_agent
from cai.agents.report import report_agent

# ── Default model tiers ──────────────────────────────────────────────
# Per-agent env vars (CAI_ORCH_MODEL, etc.) take priority over these.
# These are only fallback defaults — intentionally small to avoid
# 90GB+ VRAM usage from models like qwen3.5:122b.
DEFAULT_BIG   = "qwen2.5:72b"
DEFAULT_MED   = "qwen2.5:32b"
DEFAULT_SMALL = "qwen3:14b"

logger = logging.getLogger(__name__)


def _get_ollama_base_url() -> str:
    """Return the Ollama server base URL (without /v1 suffix)."""
    base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")
    # OLLAMA_API_BASE often ends with /v1 for OpenAI compat, strip it
    base = base.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base


def _verify_ollama_models() -> None:
    """Check that all required models are available in Ollama.

    Queries the Ollama /api/tags endpoint and warns for each model that
    is not pulled.  Never raises — failures are logged as warnings so
    the pattern can still load (the model might be pulled later).
    """
    # Collect the actual model names that will be used (env override or default)
    required = {
        "Orchestrator": os.getenv("CAI_ORCH_MODEL", DEFAULT_BIG),
        "Recon":        os.getenv("CAI_RECON_MODEL", DEFAULT_SMALL),
        "Strategy":     os.getenv("CAI_STRATEGY_MODEL", DEFAULT_BIG),
        "Exploitation": os.getenv("CAI_EXPLOIT_MODEL", DEFAULT_MED),
        "PrivEsc":      os.getenv("CAI_PRIVESC_MODEL", DEFAULT_MED),
        "Report":       os.getenv("CAI_REPORT_MODEL", DEFAULT_SMALL),
    }

    try:
        url = f"{_get_ollama_base_url()}/api/tags"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        available = {m["name"] for m in data.get("models", [])}
    except Exception as exc:
        logger.warning(
            "Could not query Ollama at %s/api/tags: %s — "
            "skipping model verification", _get_ollama_base_url(), exc,
        )
        return

    unique_models = set(required.values())
    missing = unique_models - available
    if missing:
        # Also try matching without tag (e.g. "qwen3:14b" matches "qwen3:14b")
        # Ollama sometimes reports with ":latest" suffix
        available_base = {m.split(":")[0] for m in available}
        still_missing = []
        for m in missing:
            base_name = m.split(":")[0]
            if base_name not in available_base:
                still_missing.append(m)

        if still_missing:
            agents_affected = [
                f"{agent} ({model})"
                for agent, model in required.items()
                if model in still_missing
            ]
            logger.warning(
                "Ollama models NOT available: %s — affected agents: %s. "
                "Pull them with: %s",
                ", ".join(still_missing),
                ", ".join(agents_affected),
                " && ".join(f"ollama pull {m}" for m in still_missing),
            )


# ── Verify models at import time ─────────────────────────────────────
_verify_ollama_models()


def _make_model(env_var: str, default: str, agent_name: str):
    return OpenAIChatCompletionsModel(
        model=os.getenv(env_var, default),
        openai_client=AsyncOpenAI(),
        agent_name=agent_name,
    )


# ── Clone agents (avoid mutating the originals) ─────────────────────
_orchestrator = orchestrator_agent.clone()
_recon        = recon_agent.clone()
_strategy     = strategy_agent.clone()
_exploitation = exploitation_agent.clone()
_privesc      = privesc_agent.clone()
_report       = report_agent.clone()

# ── Assign per-agent models and lock them ────────────────────────────
_orchestrator.model = _make_model("CAI_ORCH_MODEL",     DEFAULT_BIG,   _orchestrator.name)
_recon.model        = _make_model("CAI_RECON_MODEL",    DEFAULT_SMALL, _recon.name)
_strategy.model     = _make_model("CAI_STRATEGY_MODEL", DEFAULT_BIG,   _strategy.name)
_exploitation.model = _make_model("CAI_EXPLOIT_MODEL",  DEFAULT_MED,   _exploitation.name)
_privesc.model      = _make_model("CAI_PRIVESC_MODEL",  DEFAULT_MED,   _privesc.name)
_report.model       = _make_model("CAI_REPORT_MODEL",   DEFAULT_SMALL, _report.name)

for _a in [_orchestrator, _recon, _strategy, _exploitation, _privesc, _report]:
    _a._lock_model = True
    _a.isolated_context = True
del _a

# Specialists must hand back to Orchestrator — they cannot end the session.
for _a in [_recon, _strategy, _exploitation, _privesc]:
    _a.can_finish = False
del _a

# ── Handoffs — hub-and-spoke topology ────────────────────────────────

# Orchestrator delegates to any specialist
_orchestrator.handoffs = [
    handoff(agent=_recon,
            tool_description_override="Delegate to Recon Agent for port scanning, service enumeration, and directory fuzzing"),
    handoff(agent=_strategy,
            tool_description_override="Delegate to Strategy Agent for analyzing findings and defining the attack plan"),
    handoff(agent=_exploitation,
            tool_description_override="Delegate to Exploitation Agent for exploiting identified vulnerabilities"),
    handoff(agent=_privesc,
            tool_description_override="Delegate to PrivEsc Agent for privilege escalation after initial access"),
    handoff(agent=_report,
            tool_description_override="Delegate to Report Agent for documenting findings and generating the final report"),
]

# Every specialist hands back to the Orchestrator
_orch_handoff = handoff(
    agent=_orchestrator,
    tool_description_override="Hand off back to the Orchestrator to decide the next phase"
)

_recon.handoffs        = [_orch_handoff]
_strategy.handoffs     = [_orch_handoff]
_exploitation.handoffs = [_orch_handoff]
_privesc.handoffs      = [_orch_handoff]
_report.handoffs       = [_orch_handoff]

# ── Entry point ──────────────────────────────────────────────────────
redteam_orchestrated_pattern = _orchestrator
redteam_orchestrated_pattern.pattern = "swarm"

_recon.pattern        = "swarm"
_strategy.pattern     = "swarm"
_exploitation.pattern = "swarm"
_privesc.pattern      = "swarm"
_report.pattern       = "swarm"
