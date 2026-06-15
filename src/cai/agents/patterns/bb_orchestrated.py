"""
Orchestrated Bug Bounty Swarm Pattern

6-agent structure for full bug bounty lifecycle, from recon to report:

  BB Coordinator (hub)
  ├── Recon & Scope      — subdomain enum, port scanning, asset discovery
  ├── Web Analyzer       — endpoint mapping, auth flows, threat modeling
  ├── Vulnerability Hunter — active vuln testing (SQLi, XSS, SSRF, IDOR)
  ├── Exploit & PoC      — PoC development and severity assessment
  └── Report & Triage    — platform-ready vulnerability reports

Difference from bb_triage_swarm_pattern:
- bb_triage has only 2 agents (Bug Bounter + Retester), focused on
  reconnaissance and verification.
- This pattern covers the FULL lifecycle including exploitation,
  PoC development, and structured reporting with severity assessment.

Per-agent models can be overridden with environment variables:
  CAI_BB_COORD_MODEL, CAI_BB_RECON_MODEL, CAI_BB_ANALYZER_MODEL,
  CAI_BB_HUNTER_MODEL, CAI_BB_EXPLOIT_MODEL, CAI_BB_REPORT_MODEL
"""

import os
from openai import AsyncOpenAI
from cai.sdk.agents import handoff, OpenAIChatCompletionsModel

from cai.agents.bb_coordinator import bb_coordinator_agent
from cai.agents.bb_recon import bb_recon_agent
from cai.agents.bb_web_analyzer import bb_web_analyzer_agent
from cai.agents.bb_vulnhunter import bb_vulnhunter_agent
from cai.agents.bb_exploit import bb_exploit_agent
from cai.agents.bb_report import bb_report_agent

# ── Default model tiers ──────────────────────────────────────────────
DEFAULT_BIG   = "qwen2.5:32b"
DEFAULT_MED   = "qwen3:14b"
DEFAULT_SMALL = "qwen3:8b"


def _make_model(env_var: str, default: str, agent_name: str):
    return OpenAIChatCompletionsModel(
        model=os.getenv(env_var, default),
        openai_client=AsyncOpenAI(),
        agent_name=agent_name,
    )


# ── Clone agents ─────────────────────────────────────────────────────
_coordinator  = bb_coordinator_agent.clone()
_recon        = bb_recon_agent.clone()
_web_analyzer = bb_web_analyzer_agent.clone()
_vulnhunter   = bb_vulnhunter_agent.clone()
_exploit      = bb_exploit_agent.clone()
_report       = bb_report_agent.clone()

# ── Assign per-agent models and lock ─────────────────────────────────
_coordinator.model  = _make_model("CAI_BB_COORD_MODEL",    DEFAULT_BIG,   _coordinator.name)
_recon.model        = _make_model("CAI_BB_RECON_MODEL",    DEFAULT_SMALL, _recon.name)
_web_analyzer.model = _make_model("CAI_BB_ANALYZER_MODEL", DEFAULT_MED,   _web_analyzer.name)
_vulnhunter.model   = _make_model("CAI_BB_HUNTER_MODEL",  DEFAULT_MED,   _vulnhunter.name)
_exploit.model      = _make_model("CAI_BB_EXPLOIT_MODEL",  DEFAULT_MED,   _exploit.name)
_report.model       = _make_model("CAI_BB_REPORT_MODEL",  DEFAULT_SMALL, _report.name)

for _a in [_coordinator, _recon, _web_analyzer, _vulnhunter, _exploit, _report]:
    _a._lock_model = True
del _a

# ── Handoffs — hub-and-spoke ─────────────────────────────────────────

_coordinator.handoffs = [
    handoff(agent=_recon,
            tool_description_override="Delegate to Recon & Scope for subdomain enumeration, port scanning, and asset discovery"),
    handoff(agent=_web_analyzer,
            tool_description_override="Delegate to Web Analyzer for deep endpoint mapping, auth flow analysis, and threat modeling"),
    handoff(agent=_vulnhunter,
            tool_description_override="Delegate to Vulnerability Hunter for active vulnerability testing (SQLi, XSS, SSRF, IDOR)"),
    handoff(agent=_exploit,
            tool_description_override="Delegate to Exploit & PoC for proof-of-concept development and severity validation"),
    handoff(agent=_report,
            tool_description_override="Delegate to Report & Triage for documenting findings and generating platform-ready reports"),
]

_coord_handoff = handoff(
    agent=_coordinator,
    tool_description_override="Hand off back to the BB Coordinator to decide the next phase"
)

_recon.handoffs        = [_coord_handoff]
_web_analyzer.handoffs = [_coord_handoff]
_vulnhunter.handoffs   = [_coord_handoff]
_exploit.handoffs      = [_coord_handoff]
_report.handoffs       = [_coord_handoff]

# ── Entry point ──────────────────────────────────────────────────────
bb_orchestrated_pattern = _coordinator
bb_orchestrated_pattern.pattern = "swarm"

_recon.pattern        = "swarm"
_web_analyzer.pattern = "swarm"
_vulnhunter.pattern   = "swarm"
_exploit.pattern      = "swarm"
_report.pattern       = "swarm"
