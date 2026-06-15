# CAI technical guide: an agent framework for cybersecurity

## What is CAI?

CAI (*Cybersecurity AI*) is an AI-agent framework for offensive security work. It offers an interactive command-line interface (a REPL) from which you launch a single agent, or a coordinated team of agents, with access to real security tools: port scanning, web fuzzing, SQL injection, password cracking, privilege escalation, and so on.

Internally, each agent is an LLM with a specialized system prompt and a set of tools. The framework runs the execution loop: the model picks a tool, runs it, processes the result, and decides the next step, working on its own until it reaches the goal or the operator steps in.

This fork adds full support for local models through **Ollama** (qwen2.5, qwen3, llama3.3, and others) alongside the usual cloud models (GPT-4, Claude, and so on), so you can work in air-gapped environments or under privacy constraints.

---

## 1. Orchestrated multi-agent patterns

### Orchestrated Red Team

**Files:** `src/cai/agents/orchestrator.py`, `recon.py`, `strategy.py`, `exploitation.py`, `privesc.py`, `report.py`  
**Pattern:** `src/cai/agents/patterns/redteam_orchestrated.py`  
**Prompts:** `src/cai/prompts/system_orchestrator_agent.md`, `system_recon_agent.md`, `system_strategy_agent.md`, `system_exploitation_agent.md`, `system_privesc_agent.md`, `system_report_agent.md`

A team of six specialized agents works in a hub-and-spoke topology under a central orchestrator:

| Agent | Role |
|-------|------|
| **Orchestrator** | Central coordinator. Takes the pentest goal, decides which specialist acts at each point, and keeps the overall state of the attack. Does not run commands itself. |
| **Recon** | Reconnaissance: port scanning (nmap), service enumeration, directory fuzzing (gobuster/ffuf), and attack-surface discovery. |
| **Strategy** | Analyzes the reconnaissance findings and writes a prioritized attack plan. It has no execution tools; it only reasons and writes the plan. |
| **Exploitation** | Runs the planned attacks: SQLi (sqlmap), brute force (hydra), known exploits, and so on. |
| **PrivEsc** | Privilege escalation. After initial access, looks for ways to reach root: SUID binaries, kernel exploits, misconfigured cron jobs, `sudo -l`, and similar. |
| **Report** | Collects the evidence and produces a structured Markdown pentest report with severities, remediations, and a timeline. |

To launch the Red Team pattern, select it through the `CAI_AGENT_TYPE` variable:

```bash
CAI_AGENT_TYPE="redteam_orchestrated_pattern" cai --prompt "Pentest 172.17.0.2 and get root"
```

Each agent uses a different model, assigned by complexity tier. The models are configurable through environment variables:

| Variable | Default | Agent |
|----------|---------|-------|
| `CAI_ORCH_MODEL` | `qwen2.5:72b` | Orchestrator |
| `CAI_RECON_MODEL` | `qwen3:14b` | Recon |
| `CAI_STRATEGY_MODEL` | `qwen2.5:72b` | Strategy |
| `CAI_EXPLOIT_MODEL` | `qwen2.5:32b` | Exploitation |
| `CAI_PRIVESC_MODEL` | `qwen2.5:32b` | PrivEsc |
| `CAI_REPORT_MODEL` | `qwen3:14b` | Report |

### Orchestrated Bug Bounty

**Files:** `src/cai/agents/bb_coordinator.py`, `bb_recon.py`, `bb_web_analyzer.py`, `bb_vulnhunter.py`, `bb_exploit.py`, `bb_report.py`  
**Pattern:** `src/cai/agents/patterns/bb_orchestrated.py`  
**Prompts:** `src/cai/prompts/system_bb_coordinator_agent.md` and equivalents

A team analogous to the Red Team but aimed at bug bounty programs: strict respect for the program scope, controlled exploitation to demonstrate impact (PoC), and reports in the format of platforms like HackerOne or Bugcrowd, with CVSS criteria.

```bash
CAI_AGENT_TYPE="bb_orchestrated_pattern" cai --prompt "Assess https://target.example.com (scope: *.example.com)"
```

### Multi-model support in a swarm

**Files:** `src/cai/agents/patterns/multi_model_swarm.py`, `multi_model_redteam.py`  
**Infrastructure:** `src/cai/sdk/agents/agent.py`, `src/cai/agents/factory.py`, `src/cai/agents/__init__.py`, `src/cai/cli.py`

The original framework assumes every agent uses the same LLM: the model is read from `CAI_MODEL` and the factory propagates it to each agent on clone. That design is incompatible with an orchestrated team where each agent needs a different model for reasons of cost and capability (a 72B model for strategic reasoning, a 14B for fast reconnaissance, and so on).

Four points in the framework broke the multi-model assignment. They were changed together.

#### Problem 1: the factory always overwrites the model

`factory.py` builds an `OpenAIChatCompletionsModel` from `CAI_MODEL` (or the agent's env var) **every time**, regardless of whether the agent already had a model assigned by the pattern. On clone, that fixed model is lost.

**Fix in `factory.py`:** before cloning, it checks whether the original agent has `_lock_model=True`. If so, and there is no explicit `model_override` from the user, it keeps the original model instead of replacing it. After the clone, the `_lock_model` attribute is copied to the clone by hand (it is not a dataclass field, and `dataclasses.replace()` does not carry it over).

#### Problem 2: the CLI overwrites models after handoffs

`cli.py` calls `update_agent_models_recursively()` at two moments: on startup and after every handoff. That function walks the agent graph and replaces every agent's model with the one currently active in the CLI.

**Fix in `cli.py`:** the function skips an agent when `_lock_model=True`. The same applies to the main loop and to the code that updates the active agent after a streaming handoff.

#### Problem 3: the agent registry overwrites the real agent with a pseudo-object

`agents/__init__.py` walks the `PATTERNS` dictionary and creates a `PatternAgent` (a minimal object with `handoffs=[]`, `model=None`) for each registered pattern. That loop runs **after** the pattern module has already exported the real agent (with handoffs wired, a model assigned, and `_lock_model=True`). The result: `redteam_orchestrated_pattern`, the real orchestrator with the full topology, was overwritten by an empty `PatternAgent` before the user could select it.

**Fix in `agents/__init__.py`:** the pseudo-agent loop checks whether a real `Agent` is already registered under that name. If so, it keeps it and skips the `PatternAgent`.

#### Problem 4: `_lock_model` did not exist on the `Agent` dataclass

The three points above depended on a `_lock_model` field that the SDK's `Agent` dataclass did not have. Without declaring it as a field, the attribute was dynamic: it was lost on any call to `agent.clone()` or `dataclasses.replace()`, which made the protection fragile and dependent on the order of operations.

**Fix in `agent.py`:** `_lock_model: bool = False` was declared as a dataclass field, along with `isolated_context: bool = False`, `can_finish: bool = True`, and `_isolated_items_offset: int = 0` (see sections 2 and 3).

---

## 2. Per-agent isolated context

**Files:** `src/cai/sdk/agents/agent.py`, `src/cai/sdk/agents/run.py`

### The problem: shared history in multi-agent swarms

The original framework hands context between agents like this: on each handoff, the receiving agent's `message_history` is set by reference to the sending agent's:

```python
# Original behavior (cai-repo/run.py)
current_agent.model.message_history = previous_agent.model.message_history
```

In a swarm of six agents running a pentest over several hours, this sets off a chain of problems.

#### Context overflow

Each time a specialist returns control to the Orchestrator and it delegates again, the receiver gets the full message list of every prior agent. After three or four full cycles (Orch→Recon→Orch→Strategy→Orch→Exploit, and so on), the accumulated history exceeds the context window of local models (~32K tokens). At that point the model degrades steadily: it ignores earlier instructions, repeats steps already done, or returns incoherent answers.

#### Agent identity confusion

A subtler and more immediate problem is identity. When agent B receives A's full history, that history holds `assistant` messages under A's name, tools A ran, and A's reasoning. B's model sees a conversation where "someone" (A) was already doing reconnaissance with nmap, had already found ports, had already started a strategy. Since the LLM has no notion of "I am B, not A", it tends to continue the line of work it finds in the context and takes on the previous agent's role. In practice this showed up as:

- The Strategy agent running nmap commands because "that is what was being done", even though it does not have `generic_linux_command` in its tool list, or has it but should not use it.
- The Orchestrator, on regaining control after Recon, relaunching reconnaissance scans instead of deciding the next strategic step, because the last work it "remembers doing" is reconnaissance.
- The Exploitation agent trying to hand off to the wrong agent, or reusing a `tool_call_id` from a tool Recon invoked to continue that execution.

#### Orphan tool calls and silent hangs

When A runs a tool and hands off before getting the result (or the result was processed and added to `generated_items` but not to `message_history`), B inherits an invalid sequence: there is an `assistant` message with `tool_calls` but no matching `tool` response message. Ollama and some OpenAI backends reject these sequences silently or with cryptic errors, which leaves the new agent hanging with no output.

#### Duplication on round-trip handoffs

If A→B→A share the same list by reference, then when B adds its own tool calls during its turn, A sees them on regaining control. On A's next turn the framework builds `input` by concatenating `original_input + generated_items`, but `generated_items` already holds B's items, which are now also in the (shared) `message_history`. A's model receives those messages twice, which confuses it about what is done and what is pending.

### The solution: isolated context with a structured briefing

The `isolated_context: bool = False` field was added to the `Agent` dataclass. When it is on:

- Each agent keeps its own **independent** `message_history`, never shared by reference. The list is broken explicitly at the handoff: `to_agent.model.message_history = []`.
- At each handoff, instead of copying the raw history, a **compact structured briefing** is built and injected as the single user message in the receiving agent's history.

The briefing is built in `_inject_handoff_context()`, which parses the sending agent's history semantically and organizes it into sections:

| Section | Content |
|---------|---------|
| `## Objective` | The first non-empty user message that the system did not generate: the operator's original goal. This guarantees the target IP/URL always reaches the specialist, even after several intermediate handoffs. |
| `## User Instructions (HIGH PRIORITY)` | Extra operator instructions sent **after** the last received briefing. Only instructions after the last `[Handoff from ...]` are included, to avoid duplicating them in circular cycles (A→B→A→C). |
| `## Commands Executed` | The last 15 commands the source agent ran. Calls to `write_key_findings`, `read_key_findings`, `thought`, and `think` are excluded: their content is already in `state.txt`. |
| `## Key Tool Outputs` | Fragments of the tool outputs, each truncated to 800 characters. |
| `## Agent Conclusion` | The source agent's last text message (its reasoning or summary before the handoff). |
| `## Current Findings (state.txt)` | The contents of the active workspace's `state.txt`, truncated to 1500 characters. |

Briefings from the same source agent are replaced rather than accumulated: if Recon hands off to the Orchestrator twice, the second briefing overwrites the first in the Orchestrator's history. The total number of briefings from different sources is capped at 3 per agent.

```bash
export CAI_HANDOFF_CONTEXT_MESSAGES=10   # source-history messages used to build the briefing
```

### The offset problem in `generated_items`

The runner keeps a global `generated_items` list with every `RunItem` produced during the session, from any agent. When an agent with `isolated_context=True` runs a turn, passing it all of those items (as the original path does) would give it the work of every other agent, undoing the isolation and bringing back the identity and duplication problems above.

The `_isolated_items_offset: int = 0` field was added to the `Agent` dataclass. It records the index in `generated_items` from which this agent should read on each turn. Declaring it as a dataclass field (rather than a dynamic attribute set after instantiation) makes it survive `agent.clone()` and `dataclasses.replace()`: if it were dynamic, it would be lost on each clone and the agent would reprocess every item from the start.

The offset update flow:

1. On the A→B handoff, the runner records `to_agent._isolated_items_offset = len(generated_items)`.
2. When B runs its turn, it filters `generated_items[offset:]` and includes only items where `item.agent.name == agent.name`.
3. At the end of the turn, it updates `agent._isolated_items_offset = len(generated_items)` for the next one.

This also resolves the round-trip: when B returns to A (A→B→A), A sees only the items it produced itself since the offset recorded at the last handoff that reached it.

### Orphan tool calls: history sanitizing

With `isolated_context=False` (original behavior), the shared history can hold `tool_calls` from the previous agent whose `tool` response messages never reached `message_history` (because they were processed in `generated_items`). `_sanitize_tool_call_pairs()` was added in `openai_chatcompletions.py`. It scans the history before sending it to the LLM, finds `tool_calls` with no matching response, and inserts placeholder responses `[handoff — tool processed by previous agent]` so the sequence is valid.

### Preserving HITL instructions

With `isolated_context=True`, the `original_input` the runner passes to `_run_single_turn` is discarded (the agent uses its own `message_history`). This made operator instructions entered through the Ctrl+C prompt (HITL) vanish silently: the active agent never received them.

A prior extraction step was added: before discarding `original_input`, it looks for the last user message that is not a system message (`"Continue with your task..."`, briefings, warnings). If that message does not already match the last `user` in `message_history`, it is added explicitly and logged in the JSONL with the `_hitl_logged` flag, to avoid duplicating it if the same `original_input` is reused across several turns.

---

## 3. Session-finish control (`can_finish`)

**Files:** `src/cai/sdk/agents/agent.py`, `src/cai/sdk/agents/_run_impl.py`, `src/cai/agents/patterns/redteam_orchestrated.py`

The `can_finish` field was added to the base agent definition. When `can_finish=False`, if the agent produces a response with no tool calls (which would normally end the session), the framework automatically forces a handoff to the first agent in its handoff list instead of closing the session.

In the orchestrated Red Team pattern, the Recon, Strategy, Exploitation, and PrivEsc agents have `can_finish=False`. Only the Orchestrator and Report can close the session, which keeps a specialist from ending the run by accident when it emits text without calling a tool.

---

## 4. Command repetition detection

**Files:** `src/cai/sdk/agents/repetition_detector.py`, `src/cai/sdk/agents/run.py`

A repetition detector watches the commands each agent runs. If the same command (normalized, ignoring paths, URLs, and specific strings) repeats N times in a row, the framework injects a `WARNING` into the agent's history telling it to change strategy.

The threshold is configurable:

```bash
export CAI_REPEAT_THRESHOLD=3   # default: 3 repetitions
```

The detector resets at each handoff, since the receiving agent is in a different context.

---

## 5. Tool Profiles system

**Files:** `src/cai/tools/reconnaissance/tool_profiles/__init__.py` and the individual profiles in that same directory  
**Integration:** `src/cai/tools/reconnaissance/generic_linux_command.py`

A modular pre- and post-processing layer was added for the security tools. Each profile is a standalone Python file that exports a `PROFILE` variable of type `ToolProfile` and is auto-discovered on package import, with no manual registration.

### Pre-processing: smart defaults

Before a command runs, the framework finds the first profile whose regex matches the command and applies the **smart defaults**: extra flags the tool needs to run correctly in a non-interactive way.

| Tool | Smart default applied |
|------|----------------------|
| `sqlmap` | Adds `--forms --crawl=2` when the URL has no GET parameters. Detects and skips the case where `--data` is already present. |
| `john` | Adds `--wordlist=/usr/share/wordlists/rockyou.txt` when no mode is given. |

### Post-processing: output summary

After execution, a profile can process the raw output and return a structured summary, which cuts token use in the LLM's context:

| Tool | Post-processing |
|------|----------------|
| `nmap` | Extracts an `--- OPEN PORTS SUMMARY ---` with open ports and services |
| `hydra` | Extracts the credentials found (`login: X password: Y`) |
| `john` / `hashcat` | Extracts the cracked hashes |
| `gobuster` / `ffuf` / `dirb` | Extracts the discovered paths/endpoints with their status codes |
| `nikto` / `wpscan` | Extracts the security findings |
| `whatweb` | Extracts the detected technologies |
| `searchsploit` | Extracts the exploits found |
| `enum4linux` | Extracts users, shares, and groups |
| `wfuzz` | Extracts the hits (non-filtered responses) |

### Help-page detection

A profile can declare `help_indicators`: if every indicator is present in the output, the profile decides the tool printed its help instead of running (wordlist not found, wrong parameters, and so on) and replaces the output with a clear message that guides the model to fix the command.

### Per-profile timeout control

A profile can set:
- `idle_timeout`: the maximum time with no output before the process is killed (default: 10s)
- `max_execution_time`: the total execution limit (default: 0 = no limit)

The `sqlmap` profile uses `idle_timeout=120` (to handle time-based blind SQLi with `SLEEP(5)`) and `max_execution_time=300` (a 5-minute cap per invocation).

To turn off the smart defaults globally:

```bash
export CAI_TOOL_SMART_DEFAULTS=false
```

---

## 6. Command-execution improvements

**File:** `src/cai/tools/common.py`

Support for `idle_timeout` and `max_execution_time` was added as parameters in the framework's four execution functions (`_run_local_async`, `_run_docker_async`, `run_command_async`, `run_command`). When `max_execution_time` is exceeded, the whole process tree is killed (not just the parent), which is needed for tools that spawn child processes, like sqlmap.

---

## 7. Ollama model support

**File:** `src/cai/sdk/agents/models/openai_chatcompletions.py`

Full support for local models through Ollama was added:

- **Automatic detection:** turns on when `OLLAMA_API_BASE` is set in the environment.
- **Configurable timeout:** to keep requests to large models (72B) from hanging forever:
  ```bash
  export CAI_MODEL_TIMEOUT=300   # default: 300s
  ```
- **More retries:** up to 5 retries (vs. 3 in the original) with backoff, to cover load failures on shared servers.
- **Clear error messages:** if the model is not installed in Ollama, the framework reports the exact command to install it (`ollama pull <model>`).
- **Retry on empty response:** models with internal reasoning (qwen3) sometimes spend all their tokens on `<think>...</think>` and return an empty response. The framework retries automatically up to 3 times with backoff.

---

## 8. Context compaction system

**Files:** `src/cai/sdk/agents/models/openai_chatcompletions.py`, `src/cai/repl/commands/memory.py`

### The problem: auto-compact never fired with local models

The original framework already had an auto-compaction mechanism (`_auto_compact_if_needed`). Its logic: before each request to the LLM, it estimates the input's token count; if it exceeds the threshold (`max_tokens × threshold`), it compacts the context. The problem was in the `max_tokens` calculation.

The original `_get_model_max_tokens()` looked the model up in `pricing.json` and, when it did not find it, returned `200000` as a universal fallback:

```python
# Original (cai-repo)
def _get_model_max_tokens(self, model_name: str) -> int:
    # ...looks it up in pricing.json...
    return 200000  # fallback for any model not found
```

`pricing.json` only holds cloud models (GPT-4, Claude, and so on). Local Ollama models, with real context windows of 8K to 32K tokens depending on their configuration, never appear in that file. The result: for `qwen3:14b` (32K real), `max_tokens` was 200000, the threshold landed at 160000 tokens, and that threshold was never reached. Auto-compaction was inert for any Ollama model, and the history grew until the model degenerated.

### The solution: dynamic resolution of the real context

`_get_model_max_tokens()` was rewritten with this resolution order:

1. **`pricing.json`:** cloud models with known information.
2. **In-memory cache** (`_ollama_context_cache`): the result of a previous query to Ollama, to avoid repeating the HTTP request every turn.
3. **Live query to Ollama's `/api/show`:** extracts the `context_length` field from the `model_info` the local server returns. The result is cached.
4. **Conservative fallback:** 32768 if `OLLAMA_API_BASE` is set (unknown Ollama model), 200000 if not (unknown cloud model).

```bash
export CAI_OLLAMA_FALLBACK_CTX=32768   # fallback when /api/show does not respond
export CAI_AUTO_COMPACT=true
export CAI_AUTO_COMPACT_THRESHOLD=0.8  # fires at 80% of the real context
```

With this fix, for `qwen3:14b` with a 32768-token context, the threshold becomes ~26000 tokens, a value reached in real sessions, and compaction fires while the model can still process the summary.

### Compaction compatible with isolated context

The second problem was that the original compaction used `AGENT_MANAGER` to get the history of the agent being summarized:

```python
# Original: delegates to AGENT_MANAGER
summary = await MEMORY_COMMAND_INSTANCE._ai_summarize_history(agent_name)
```

With `isolated_context=True`, each agent keeps its own `model.message_history`, disconnected from the shared history that `AGENT_MANAGER` knows. On compaction, `AGENT_MANAGER` returned the wrong history (possibly empty or belonging to another agent), and the summary was useless or incorrect.

A `history_override` parameter was added to `_ai_summarize_history()`, and the call in `_auto_compact_if_needed` was changed to pass the model's real history directly:

```python
# Modified: uses the agent's real history, not AGENT_MANAGER's
summary = await MEMORY_COMMAND_INSTANCE._ai_summarize_history(
    self.agent_name,
    history_override=list(self.message_history),   # real history, not the manager's
    prompt_override=self.AUTO_COMPACT_BRIEFING_PROMPT,
)
```

### Structured compaction prompt

`AUTO_COMPACT_BRIEFING_PROMPT` was added as a class constant in `OpenAIChatCompletionsModel`. This prompt tells the LLM to write the summary in the same section format the handoff briefings use (`## Objective`, `## Commands Executed`, `## Key Findings`, `## Current Status`, `## Next Steps`). As a result, the agent can consume the compacted context the same way it consumes a handoff briefing, with no change to the later parsing.

### The agent's system prompt is not discarded

A common question when learning how compaction works is whether the agent's system prompt (its role instructions, available tools, response format) also disappears when the history is cleared. The answer is no.

`_auto_compact_if_needed` receives `system_instructions` as a separate parameter. After it generates the summary, it appends it to the end of the original system prompt and returns the augmented version:

```python
new_system_instructions = system_instructions or ""   # original system prompt intact
new_system_instructions += f"\n\nPrevious conversation summary:\n{summary}"
```

On the next turn, the model receives:

```
[system]  <original_agent_instructions>

Previous conversation summary:
## Objective
...
## Commands Executed
...
```

The agent's role and capabilities stay intact. Only `message_history` (the conversation turns) is emptied. The compact summary travels in the system prompt, not as an extra user message.

### The summary agent did not use Ollama

The agent that generates the compaction summary (`Summary Agent` in `_ai_summarize_history`) builds an `AsyncOpenAI` internally to call the LLM. Before the fix, this client was always created pointing at the OpenAI API:

```python
# Before (cai-repo and earlier versions)
openai_client=AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
```

When the user works with Ollama (`OLLAMA_API_BASE` set), this call went to `api.openai.com` instead of the local server. The result was a silent failure (model not found, or an auth error when there was no OpenAI key), and `_auto_compact_if_needed` carried on with the full, uncompacted history.

Detection of the active backend was added before the client is created:

```python
# Now (this fork)
ollama_base = os.getenv("OLLAMA_API_BASE")
if ollama_base:
    base_url = ollama_base if ollama_base.endswith("/v1") else f"{ollama_base}/v1"
    client = AsyncOpenAI(api_key=os.getenv("OLLAMA_API_KEY") or "ollama", base_url=base_url)
else:
    client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
```

The model used to generate the summary is the same one active in the agent (`CAI_MODEL` or the model configured for that agent), so compaction uses the same backend as the rest of the session.

### Fixing a crash when applying the summary

In the original version, `COMPACTED_SUMMARIES[agent_name]` was a string. The code that applied the summary to the history called `.append()` on it in some paths, raising an `AttributeError` when it tried to concatenate strings. This was fixed by always storing the summary as a list (`[summary]`) and filling `APPLIED_MEMORY_IDS` with a temporary ID (`auto_<timestamp>`) to avoid the crash in the apply path.

---

## 9. Detecting tool calls written as text

**File:** `src/cai/sdk/agents/_run_impl.py`

Small local models (qwen3:8b, llama3.3, and others) do not use the native function-calling mechanism reliably: they often write the tool call as plain text in the response. A chained detection system was added that recognizes four distinct patterns:

1. **Python style:** `generic_linux_command(command="nmap -sV 10.0.0.1")`
2. **Standard JSON:** `{"name": "generic_linux_command", "parameters": {...}}`
3. **JSON with fuzzy matching:** if the model invents a name like `"delegate"` with an `"agent": "Recon Agent"` field, it is resolved to the correct handoff.
4. **Markdown code blocks:** ` ```bash\nnmap 10.0.0.1\n``` ` is converted automatically to `generic_linux_command(command="nmap 10.0.0.1")`.

Detection is case-insensitive (`Think(thought=...)`, `GENERIC_LINUX_COMMAND(...)`, and `Generic_Linux_Command(...)` are equivalent). The special tokens Ollama inserts (`<|python_tag|>`, `<|im_start|>`, `<|im_end|>`) are stripped before parsing.

---

## 10. Web-scanning MCP servers

Two MCP servers were added to connect web scanners with the CAI agents. MCP (*Model Context Protocol*) is the standard protocol that lets LLMs invoke external tools as if they were native functions.

### Burp Suite Professional

**Files:** `examples/mcp/burpsuite_example/server.py`, `examples/mcp/burpsuite_example/README.md`

An MCP server that exposes the Burp Suite Professional REST API was added. It needs the **Professional** edition: the Community edition does not fully support the legacy REST API (`/v0.1`), so many tools fail or return authorization errors.

| Tool | Function |
|------|----------|
| `burp_scan` | Launches an active scan against a URL |
| `burp_scan_status` | Checks the status of a running scan |
| `burp_spider` | Crawls the target site |
| `burp_sitemap` | Gets the discovered site map |
| `burp_get_issues` | Lists the vulnerabilities found |
| `burp_get_issue_details` | Full detail of a vulnerability, including request/response |
| `burp_send_to_repeater` | Sends a request to Burp's Repeater |
| `burp_proxy_history` | Queries the proxy history |

**Prerequisites:**

1. Burp Suite **Professional** with the REST API enabled (`Proxy → Options → REST API`).
2. Install dependencies: `pip install "mcp[server]" requests`
3. Start the server: `python examples/mcp/burpsuite_example/server.py`
4. Load it in CAI: `/mcp load http://localhost:8000/sse burp`

```bash
export BURP_API_URL=http://localhost:1337   # default
export BURP_API_KEY=""                      # optional
```

### OWASP ZAP (free alternative)

**Files:** `examples/mcp/zap_example/server.py`, `examples/mcp/zap_example/README.md`

An equivalent MCP server was added for **OWASP ZAP**, the open-source web security scanner. It is the recommended alternative when you do not have a Burp Suite Professional license, since it exposes the same scanning functionality through its own REST API and does not carry the limits of Burp's Community edition.

| Tool | Burp equivalent | Function |
|------|-----------------|----------|
| `zap_scan` | `burp_scan` | Launches an active scan |
| `zap_scan_status` | `burp_scan_status` | Active-scan status |
| `zap_spider` | `burp_spider` | Standard crawler |
| `zap_spider_status` | — | Crawler status |
| `zap_ajax_spider` | — | Crawler for JavaScript-heavy applications |
| `zap_ajax_spider_status` | — | AJAX-crawler status |
| `zap_sitemap` | `burp_sitemap` | Discovered URLs |
| `zap_get_alerts` | `burp_get_issues` | Vulnerabilities found (filterable by risk) |
| `zap_get_alert_details` | `burp_get_issue_details` | Detail of a vulnerability with CWE/WASC |
| `zap_add_to_context` | — | Defines the scan scope |
| `zap_generate_report` | — | Produces a summary of findings grouped by severity |

**Prerequisites:**

1. OWASP ZAP installed: `sudo snap install zaproxy --classic`
2. Start it in daemon mode: `zaproxy -daemon -port 8080 -config api.disablekey=true`
3. Install dependencies: `pip install "mcp[server]" requests`
4. Start the server: `python examples/mcp/zap_example/server.py`
5. Load it in CAI: `/mcp load http://localhost:8000/sse zap`

```bash
export ZAP_API_URL=http://localhost:8080   # default
export ZAP_API_KEY=""                      # empty if api.disablekey=true
```

---

## 11. Findings persistence (`state.txt`)

**Files:** `src/cai/tools/misc/reasoning.py`, `src/cai/repl/commands/state.py`

Agents use the `write_key_findings` and `read_key_findings` tools to persist findings across handoffs in a `state.txt` file inside the active workspace. The path is resolved correctly with the `_state_file_path()` helper, which accounts for the `CAI_WORKSPACE` variable.

`write_key_findings` includes **automatic deduplication**: if the content to write is already in the file, the operation is skipped, which keeps `state.txt` from piling up identical sections after several cycles between agents.

### The `/state` command in the REPL

**File:** `src/cai/repl/commands/state.py`

The `/state` command (alias `/findings`) was added to manage `state.txt` from the interactive REPL:

| Subcommand | Action |
|------------|--------|
| `/state` or `/state show` | Shows the current contents of `state.txt` |
| `/state clear` | Deletes the file |
| `/state write <content>` | Overwrites the file (no append) |
| `/state path` | Shows the file's absolute path |

---

## 12. Continuous mode and HITL

**Files:** `src/cai/cli.py`, `src/cai/repl/commands/continue_cmd.py`

A continuous mode was added that lets the agent work on its own with no manual intervention after each turn: instead of waiting for user input, the framework injects `"Continue working on the task based on your previous findings."` automatically.

Continuous mode can be turned on two ways:

**At launch (CLI flag):**

```bash
cai --continue --prompt "Pentest 172.17.0.2 and get root"
```

**From the REPL at any time (the `/continue` command):**

**File:** `src/cai/repl/commands/continue_cmd.py`

```
/continue          # toggle on/off
/continue on       # turn continuous mode on
/continue off      # turn it off and clear the pending input
/continue status   # show current state
/cont              # short alias
```

Continuous-mode state lives in `CONTINUE_STATE` (the `continue_cmd.py` module), an object shared with `cli.py`. This lets you turn the agent's autonomy on and off mid-session without restarting it, for example after manually reviewing the output of a critical step.

You can interrupt at any time with `Ctrl+C`. At that point a **HITL prompt** (*Human-in-the-Loop*) appears that lets you:
- Type extra instructions for the active agent (injected as a `user` message in its history).
- Press Enter on an empty line to resume continuous mode.
- Press `Ctrl+C` again to return to the normal REPL prompt.

---

## 13. Environment variable reference

| Variable | Default | Function |
|----------|---------|----------|
| `CAI_ORCH_MODEL` | `qwen2.5:72b` | Orchestrator model (Red Team) |
| `CAI_RECON_MODEL` | `qwen3:14b` | Recon agent model |
| `CAI_STRATEGY_MODEL` | `qwen2.5:72b` | Strategy agent model |
| `CAI_EXPLOIT_MODEL` | `qwen2.5:32b` | Exploitation agent model |
| `CAI_PRIVESC_MODEL` | `qwen2.5:32b` | PrivEsc agent model |
| `CAI_REPORT_MODEL` | `qwen3:14b` | Report agent model |
| `CAI_MODEL_TIMEOUT` | `300` | Timeout in seconds for LLM requests |
| `CAI_AUTO_COMPACT` | `true` | Turns context auto-compact on/off |
| `CAI_AUTO_COMPACT_THRESHOLD` | `0.8` | Context percentage that fires auto-compact |
| `CAI_OLLAMA_FALLBACK_CTX` | `32768` | Fallback context length for Ollama |
| `CAI_TOOL_SMART_DEFAULTS` | `true` | Turns Tool Profile pre-processing on/off |
| `CAI_HANDOFF_CONTEXT_MESSAGES` | `10` | Source-agent messages included in the briefing |
| `CAI_REPEAT_THRESHOLD` | `3` | Repetitions before a WARNING is injected |
| `BURP_API_URL` | `http://localhost:1337` | Burp Suite REST API URL |
| `BURP_API_KEY` | `""` | Optional API key for Burp Suite |

---

## 14. Testing infrastructure

**Directory:** `tests/`

> **Note on test suite reliability**
>
> The entire test suite was generated with AI (LLM) assistance. The test cases cover the scenarios identified during development, but they cannot be treated as equivalent to a suite validated by expert human review. Some tests may check the implemented behavior rather than the correct behavior, some edge cases may go uncovered, and some mocks may not faithfully reflect the system's semantics in production. Treat the suite as a basic coverage reference and complement it with integration tests against real environments before relying on it as a correctness guarantee.

A full pytest test suite was added. The main groups are:

| File | What it verifies |
|------|-----------------|
| `tests/core/test_text_tool_call_extraction.py` | Detection of tool calls written as text: Python style, JSON, handoffs with fuzzy matching, Markdown code blocks, case-insensitive |
| `tests/core/test_isolated_context.py` | The isolated-context system: briefing injection on handoffs, no duplication on round-trips A→B→A, linear history growth |
| `tests/core/test_can_finish.py` | The `can_finish` field: default behavior, setting it to `False`, preservation on clone, correct assignment in the Red Team pattern |
| `tests/agents/test_redteam_orchestrated.py` | Red Team pattern handoffs: Orchestrator→Recon→back, full chain, max_turns, `_lock_model` |
| `tests/agents/test_redteam_tools_integration.py` | Tool Profiles in execution: that nmap/sqlmap/hydra and others run with the correct profiles |
| `tests/tools/test_tool_profiles.py` | Auto-discovery of the profiles, pattern matching, smart defaults, post-processing |
| `tests/repl/test_state_command.py` | The `/state` command: show, clear, write, subcommand dispatch |

To run the tests from the repository root:

```bash
pytest tests/ -v
```
