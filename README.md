# cai-multiagent-tfm

![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT%20%2B%20research-lightgrey)

A fork of [CAI (Cybersecurity AI)](https://github.com/aliasrobotics/cai) `cai-framework` 0.5.10 that adds orchestrated multi-agent patterns, isolated per-agent context, and a set of web-exploitation tools. It was built to evaluate autonomous pentesting with local models (Ollama), where small models call tools unreliably and a single shared context degrades quickly across handoffs. The changes target both problems: coordination between specialized agents, and runtime stability under local inference.

## What's different from upstream CAI

The file-by-file mapping is in [CHANGES.md](CHANGES.md). The main additions:

- **Two orchestrated patterns**, each a team of six agents in a hub-and-spoke topology (a central coordinator delegates to specialists, which hand control back): a Red Team pattern (Orchestrator, Recon, Strategy, Exploitation, PrivEsc, Report) and a Bug Bounty pattern.
- **Per-agent model assignment.** Each agent can run a different model, set through environment variables. A `_lock_model` flag stops the CLI from overwriting those assignments.
- **Isolated per-agent context.** Instead of one growing shared history, each agent keeps its own and receives a structured briefing at each handoff (objective, commands run, key tool outputs, findings). This keeps context from growing without bound in long swarm runs.
- **Session-finish control** (`can_finish`). Only the Orchestrator and Report agents can end a session; a specialist that replies without calling a tool is nudged back to work.
- **16 tool profiles** that pre-process commands (adding flags a tool needs to avoid failing) and post-process output (extracting a short summary from long scans). Profiles are auto-discovered.
- **Text-based tool-call and handoff detection.** Local models that write a tool call as plain text or a fenced code block instead of using function calling are detected, and the call is executed anyway.
- **Ollama support and runtime stability:** dynamic resolution of the real context window (so auto-compact actually triggers on local models), configurable request timeouts, retries on empty `<think>` responses, and process-tree termination so tools like sqlmap don't leave child processes running.
- **MCP servers** for OWASP ZAP and Burp Suite, under [examples/mcp/](examples/mcp/).
- **Native web toolkits** for XSS, JWT, LFI, and file upload, under `src/cai/tools/web/`.
- **`/state` REPL command** to inspect and reset the findings file, and a **pytest test suite** (upstream shipped none).

## Installation

Tested on Ubuntu 24.04 with Python 3.12.

```bash
git clone <repo-url> cai-multiagent-tfm
cd cai-multiagent-tfm

python3.12 -m venv cai_env
source cai_env/bin/activate

pip install -e .
```

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

Set `OLLAMA_API_BASE` to your Ollama server for local models, or an API key for a cloud provider. The orchestrated patterns default to local models, so pull them first:

```bash
ollama pull qwen2.5:72b
ollama pull qwen2.5:32b
ollama pull qwen3:14b
```

To apply the fork over an existing `cai-framework` install instead of installing from source, use `install.sh` (its header documents both modes).

## Quick start

The pattern to run is selected with the `CAI_AGENT_TYPE` variable. To launch the Red Team team against a target:

```bash
CAI_AGENT_TYPE="redteam_orchestrated_pattern" cai --prompt "Pentest 172.17.0.2 and get root"
```

Use `bb_orchestrated_pattern` for the Bug Bounty team. Per-agent models are set through environment variables:

| Variable | Default | Agent |
|----------|---------|-------|
| `CAI_ORCH_MODEL` | `qwen2.5:72b` | Orchestrator |
| `CAI_RECON_MODEL` | `qwen3:14b` | Recon |
| `CAI_STRATEGY_MODEL` | `qwen2.5:72b` | Strategy |
| `CAI_EXPLOIT_MODEL` | `qwen2.5:32b` | Exploitation |
| `CAI_PRIVESC_MODEL` | `qwen2.5:32b` | PrivEsc |
| `CAI_REPORT_MODEL` | `qwen3:14b` | Report |

`--continue` runs the agent autonomously, re-injecting a continue prompt after each turn. Interrupt with `Ctrl+C`.

## Documentation

- [docs/CAI_GUIDE.md](docs/CAI_GUIDE.md): technical guide to the fork, with the architecture and the design decisions behind each change.
- [docs/XSS_MCP_GUIDE.md](docs/XSS_MCP_GUIDE.md): running XSS challenges with the OWASP ZAP MCP server.
- [CHANGES.md](CHANGES.md): file-by-file list of every change against upstream CAI.

## Repository layout

```
src/cai/            modified CAI package
  agents/           Red Team and Bug Bounty agents, orchestration patterns
  sdk/              runner, models, isolated-context logic
  tools/            tool profiles, web toolkits, command execution
  repl/             REPL commands (includes /state)
  prompts/          agent system prompts
tests/              pytest suite
examples/mcp/       Burp Suite and OWASP ZAP MCP servers
docs/               translated guides
CHANGES.md          changes against upstream CAI
```

## Citing

This is a fork developed as part of a Master's thesis. For the original framework, cite the CAI paper:

```bibtex
@misc{mayoralvilches2025caiopenbugbountyready,
  title={CAI: An Open, Bug Bounty-Ready Cybersecurity AI},
  author={Víctor Mayoral-Vilches and Luis Javier Navarrete-Lozano and María Sanz-Gómez and Lidia Salas Espejo and Martiño Crespo-Álvarez and Francisco Oca-Gonzalez and Francesco Balassone and Alfonso Glera-Picón and Unai Ayucar-Carbajo and Jon Ander Ruiz-Alcalde and Stefan Rass and Martin Pinzger and Endika Gil-Uriarte},
  year={2025},
  eprint={2504.06017},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2504.06017},
}
```

## License

Same as upstream CAI: a combination of MIT-licensed open-source components and additions licensed for research purposes only. See [LICENSE](LICENSE) and [LICENSE-MIT](LICENSE-MIT).

## Acknowledgments

Built on [CAI](https://github.com/aliasrobotics/cai) by Alias Robotics. This fork was developed as part of a Master's thesis.
