# Guide: loading CAI's MCPs for XSS challenges

A hands-on guide to set up and launch CAI against an XSS-vulnerable VM using the
`redteam_orchestrated` pattern (hub-and-spoke, 6 agents), with OWASP ZAP as an
MCP and dalfox/XSStrike as scanners through `generic_linux_command`.

It comes out of the lessons of a real run: it spots the failures we saw (MCP not
attached, hallucinated `<tool_response>`, dalfox without a profile, lost
reflection leads) and tells you how to avoid them.


## 1. Requirements

| Component | Install on Ubuntu 24.04 | Check |
|---|---|---|
| OWASP ZAP | `sudo snap install zaproxy --classic` | `which zaproxy` |
| Chromium (for the AJAX spider) | `sudo snap install chromium` | `chromium --version` |
| dalfox | `sudo apt install golang-go && go install github.com/hahwul/dalfox/v2@latest` | `dalfox version` |
| XSStrike (optional) | `git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike` + wrapper | `xsstrike --help` |
| mcp Python SDK | already in `cai_env` | `pip show mcp` |

`$HOME/go/bin` must be on your `PATH` (add it to `~/.bashrc` if needed).


## 2. Startup (3 terminals)

### Terminal 1: ZAP in daemon mode

```bash
zaproxy -daemon -port 8080 -config api.disablekey=true
```

Leave the terminal open. Sanity check in another:
```bash
curl -s http://localhost:8080/JSON/core/view/version/
```

### Terminal 2: the ZAP MCP server

From the repository root, with the virtual environment active:

```bash
cd examples/mcp/zap_example
python server.py
```

Sanity check:
```bash
curl -N -s http://localhost:8000/sse --max-time 2 | head -5
# Should show:  event: endpoint
#               data: /messages/?session_id=...
```

### Terminal 3: CAI

```bash
source cai_env/bin/activate
cai
```


## 3. Configuration inside CAI

### 3.1 Select the pattern

```
/agent redteam_orchestrated_pattern
```

That loads the Orchestrator (hub) plus its 5 cloned specialists
(`_recon`, `_strategy`, `_exploitation`, `_privesc`, `_report`).

### 3.2 Load the MCP and wire it to the agents

```
/mcp load http://localhost:8000/sse zap
/mcp add zap recon_agent
/mcp add zap exploitation_agent
```

**Important, names:** in `/mcp add` use the **module attribute** name
(`recon_agent`, `exploitation_agent`), **NOT** the display name with spaces
(`"Recon Agent"` fails silently, because the registry indexes by attribute).

**Important, propagation to the pattern's clones:** adding the MCP to
`recon_agent` (the original module) IS enough. The pattern cloned the agents
with `dataclasses.replace`, which makes a shallow copy: the `tools` /
`mcp_servers` list is the same object in the original and in the clone, so
mutating it from `/mcp add` reaches the clone.

### 3.3 Verify

```
/mcp list              # loaded servers (should show 'zap' with N tools)
/mcp tools zap         # the concrete list: zap_spider, zap_scan, ...
/mcp associations      # which agents have which MCPs attached
```

If `/mcp associations` does not show `zap → recon_agent, exploitation_agent`,
**do not continue**: run `/mcp add` again.


## 4. Launching the attack

Recommended initial prompt for the Orchestrator (adapt the URL):

```
Goal: find and exploit XSS vulnerabilities in http://<VM-IP>/

Plan:
1. Recon: enumerate ports, fingerprint with whatweb, identify HTTP
   endpoints. For each form, extract the EXACT parameter names
   (curl -s <url> | grep -i 'input'). Use zap_spider and zap_sitemap
   to map the whole app. If it is a SPA, run zap_ajax_spider. Check
   zap_get_alerts for passive findings.

2. Strategy: prioritize parameters whose value is reflected in the
   response. Document the reflection context (HTML body, HTML
   attribute, JS string, URL) before trying payloads.

3. Exploitation:
   - For each candidate parameter, run dalfox through
     generic_linux_command. E.g.: "dalfox url 'http://<IP>/contact.php?
     nombre=1&email=a@b.c&mensaje=x' --skip-bav=true".
   - In parallel, run an active zap_scan and check zap_get_alerts
     with risk_level="High", filtering for XSS.
   - If dalfox reports issues: 0 but lists "Reflected <param> param",
     do NOT assume it is not vulnerable: try context-specific payloads
     with curl before moving on.

4. PoC: for each confirmed XSS, build the full URL with the payload
   and validate it with curl/web_request_framework. Document the
   evidence with write_key_findings.

5. Report: zap_generate_report + a list of PoCs.
```


## 5. What CAI does under the hood (details that matter)

### 5.1 Extracting tool calls from text

CAI extracts calls both through native function calling **and** by parsing the
model's text. The extractor looks, in order, for:

1. Python patterns `tool_name(key="val")` anywhere in the text (prose or code
   block).
2. JSON patterns `{"name": "...", "parameters": {...}}`.
3. As a last resort, ` ```bash ... ``` ` blocks, which it wraps as
   `generic_linux_command(command=...)`.

What this means in practice:
- If `zap_scan` **is** in the agent's tools, writing `zap_scan(target_url="...")`
  in a code block works the same as a native tool call.
- If `zap_scan` is **not** in tools (the MCP is wired wrong), that same text
  falls to step 3 and CAI tries to run `zap_scan(target_url="...")` as a shell
  command, giving `command not found`. The model then often hallucinates a
  made-up `<tool_response>`. If an agent's summary says "ZAP scan started" but
  you never see real calls, it is lying to you.

The recon and exploitation prompts already carry this warning.

### 5.2 The dalfox profile (absolute path)

`dalfox` is often invoked as `~/go/bin/dalfox ...`. The profile now matches
absolute paths too (an extended regex with a `/` separator and a negative
lookahead `(?!/)`). With the profile applied you get:

- `--silence` auto-added (the 20-line banner with ASCII art does not eat your
  context).
- `max_execution_time=600s`, `idle_timeout=60s`.
- Post-processing: the `[V]/[POC]/[R]` lines are summarized into a
  `--- DALFOX XSS FINDINGS (N) ---` block at the end.
- Help-page detection: if you pass a made-up flag (`--reflect-all` does not
  exist), CAI returns a clear error instead of the help page.


## 6. Reading dalfox results

Typical output when the endpoint reflects but nothing "pops":

```
[I] Found 9 testing points in DOM-based parameter mining
[I] Content-Type is text/html; charset=UTF-8
[I] Reflected nombre param =>
[I] Reflected email param =>
[I] Reflected mensaje param =>
[duration: 11.56s][issues: 0] Finish Scan!
```

**This does NOT mean "not vulnerable".** It means: the 3 parameters reflect
their value in the response, but the default payload bank was neutralized
(HTML-encoding, filters, CSP, an attribute context with strict quoting, and so
on). What to do:

1. `curl -s '<url-with-marker-payload>' | grep -C3 'MARKER'` to see what context
   the reflection lands in.
2. If it lands in an attribute: try breaking the attribute with `"` or `'`
   depending on the quoting (`" onmouseover=alert(1) x="`).
3. If it lands in a JS string: try `';alert(1);//`.
4. If it lands in the HTML body and `<`/`>` are encoded: try `javascript:` URLs
   in href attributes, or `onerror` in `<img>`.
5. Once you have the right payload, **rerun** dalfox with
   `--custom-payload <file>` holding variants of that payload.


## 7. Common errors and diagnosis

| Symptom | Likely cause | Fix |
|---|---|---|
| Model writes `zap_scan(...)` and "reports" success with no visible tool call | MCP not attached to the active agent | `/mcp associations` and re-add |
| `/mcp add zap "Exploitation Agent"` does nothing | Name with spaces | Use `exploitation_agent` |
| dalfox produces a huge banner and times out | Profile did not apply (absolute path before the fix) | Use a build that includes the dalfox absolute-path profile fix |
| ZAP MCP does not answer the curl | ZAP daemon not started, or port in use | `pgrep -a zaproxy`; `lsof -i:8080` |
| `zap_ajax_spider` fails | No detectable browser | `sudo snap install chromium` |
| Pattern loops Orchestrator→Exploitation with no progress | Empty findings, not enough context | Pre-fill the prompt with the form parameters |


## 8. Checklist before launching the attack

```bash
# Every binary ready
which zaproxy chromium dalfox
dalfox version
chromium --version

# ZAP + MCP server respond
curl -s http://localhost:8080/JSON/core/view/version/
curl -N -s http://localhost:8000/sse --max-time 2 | head -1

# Inside CAI
/mcp list                  # zap shows up with >=11 tools
/mcp associations          # zap → recon_agent, exploitation_agent
```

If all of the above passes, launch the prompt from section 4 and the pattern
does the rest.
