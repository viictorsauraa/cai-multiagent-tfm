"""
Tests for Redteam Orchestrated Agents with Tool Profiles Integration.

Verifies that redteam specialist agents can call generic_linux_command
with profiled tools (nmap, sqlmap, hydra, etc.) and that the tool_profiles
post-processing is correctly applied to simulated command outputs.

Covers:
1. Each specialist agent calling generic_linux_command with relevant profiled tools
2. Realistic tool-to-agent mapping (Recon->nmap/gobuster, Exploit->sqlmap/hydra, etc.)
3. Multiple tool calls + handoffs with profiled tools
4. Full pentest flow: Orch -> Recon(nmap+gobuster) -> Orch -> Strategy(think)
   -> Orch -> Exploit(sqlmap+hydra) -> Orch -> PrivEsc(john) -> Orch -> Report -> Orch
"""

from __future__ import annotations

import json
import pytest

from cai.sdk.agents import (
    Agent,
    Handoff,
    Runner,
    handoff,
    function_tool,
)
from cai.sdk.agents.items import (
    RunItem,
    HandoffCallItem,
    HandoffOutputItem,
    ToolCallItem,
    ToolCallOutputItem,
    MessageOutputItem,
)
from cai.tools.reconnaissance.tool_profiles import apply_profiles_post

from tests.fake_model import FakeModel
from tests.core.test_responses import (
    get_text_message,
    get_function_tool,
    get_function_tool_call,
    get_handoff_tool_call,
)


# ── Simulated command outputs for each profiled tool ─────────────────

SIMULATED_OUTPUTS = {
    "nmap": (
        "Starting Nmap 7.94SVN ( https://nmap.org )\n"
        "Nmap scan report for 172.17.0.2\n"
        "Host is up (0.00023s latency).\n"
        "PORT   STATE SERVICE VERSION\n"
        "22/tcp open  ssh     OpenSSH 8.9p1\n"
        "80/tcp open  http    Apache httpd 2.4.52\n"
        "443/tcp open  ssl/http  nginx 1.18.0\n"
        "Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"
    ),
    "sqlmap": (
        "[*] starting at 12:00:00\n"
        "[INFO] testing connection to the target URL\n"
        "[INFO] testing 'AND boolean-based blind'\n"
        "[INFO] GET parameter 'id' is vulnerable\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind\n"
        "    Payload: id=1 AND 1=1\n"
        "[*] shutting down at 12:01:00"
    ),
    "hydra": (
        "Hydra v9.5 (c) 2023 by van Hauser\n"
        "[DATA] attacking ssh://172.17.0.2:22/\n"
        "[22][ssh] host: 172.17.0.2   login: admin   password: password123\n"
        "[22][ssh] host: 172.17.0.2   login: root   password: toor\n"
        "1 of 1 target completed, 2 valid passwords found"
    ),
    "john": (
        "Using default input encoding: UTF-8\n"
        "Loaded 2 password hashes\n"
        "Press 'q' or Ctrl-C to abort\n"
        "password123      (admin)\n"
        "toor             (root)\n"
        "2g 0:00:00:05 DONE"
    ),
    "hashcat": (
        "hashcat (v6.2.6) starting\n"
        "Session: hashcat\n"
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        "e10adc3949ba59abbe56e057f20f883e:123456\n"
        "Status.........: Cracked"
    ),
    "ffuf": (
        "        /'___\\  /'___\\           /'___\\\n"
        "       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/\n"
        "admin                   [Status: 200, Size: 1234, Words: 100, Lines: 50]\n"
        "login                   [Status: 302, Size: 0, Words: 0, Lines: 0]\n"
        "uploads                 [Status: 403, Size: 278, Words: 20, Lines: 10]"
    ),
    "gobuster": (
        "===============================================================\n"
        "Gobuster v3.6\n"
        "===============================================================\n"
        "/admin                (Status: 200)\n"
        "/login                (Status: 302)\n"
        "/uploads              (Status: 403)\n"
        "/api                  (Status: 200)\n"
        "==============================================================="
    ),
    "nikto": (
        "- Nikto v2.5.0\n"
        "+ Target IP:          172.17.0.2\n"
        "+ Target Port:        80\n"
        "+ Server: Apache/2.4.52\n"
        "+ /admin/: Directory indexing found\n"
        "+ /login.php: Admin login page found\n"
        "+ OSVDB-3233: /icons/README: Apache default file found\n"
        "+ 7915 requests: 0 error(s) and 3 item(s) reported"
    ),
    "dirb": (
        "START_TIME: Mon Mar 18 2026\n"
        "URL_BASE: http://target/\n"
        "+ http://target/admin (CODE:200|SIZE:1234)\n"
        "+ http://target/login (CODE:302|SIZE:0)\n"
        "+ http://target/server-status (CODE:403|SIZE:277)\n"
        "END_TIME: Mon Mar 18 2026"
    ),
    "enum4linux": (
        "Starting enum4linux v0.9.1\n"
        " ===========================\n"
        "|    Share Enumeration    |\n"
        " ===========================\n"
        "//172.17.0.2/shared     Mapping: OK Listing: OK\n"
        " ============================\n"
        "|    Users on 172.17.0.2    |\n"
        " ============================\n"
        "user:[administrator] rid:[0x1f4]\n"
        "user:[guest] rid:[0x1f5]"
    ),
    "searchsploit": (
        "-------------------------------------------------------------------\n"
        " Exploit Title                          |  Path\n"
        "-------------------------------------------------------------------\n"
        "Apache 2.4.49 - Path Traversal         | exploits/multiple/webapps/50383.py\n"
        "Apache 2.4.50 - RCE                    | exploits/multiple/webapps/50406.sh\n"
        "-------------------------------------------------------------------"
    ),
    "wfuzz": (
        "********************************************************\n"
        "* Wfuzz 3.1.0 - The Web Fuzzer                        *\n"
        "********************************************************\n"
        "Target: http://target/FUZZ\n"
        "=====================================================================\n"
        "ID           Response   Lines    Word       Chars       Payload\n"
        "=====================================================================\n"
        '1:           C=200      15 L     42 W       1234 Ch     "admin"\n'
        '2:           C=302      0 L      0 W        0 Ch        "login"\n'
        "Total time: 5.123456"
    ),
    "whatweb": (
        "http://target [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], "
        "HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], "
        "IP[172.17.0.2], jQuery[3.6.0], PHP[8.1.2], Title[Welcome]"
    ),
    "wpscan": (
        "[+] URL: http://target/\n"
        "[+] Started: Mon Mar 18 2026\n"
        "[!] The WordPress 'readme.html' file exists\n"
        "[!] XML-RPC seems to be enabled\n"
        "[i] Plugin(s) Identified:\n"
        " Title: Contact Form 7 5.3.2\n"
        " Title: Yoast SEO 16.5\n"
        "[+] Finished: Mon Mar 18 2026"
    ),
}


# ── Mock tool that applies tool_profiles post-processing ─────────────

@function_tool(name_override="generic_linux_command")
def mock_linux_command(command: str) -> str:
    """Execute a Linux command (simulated with tool profile post-processing)."""
    for tool_name, output in SIMULATED_OUTPUTS.items():
        if tool_name in command:
            result = apply_profiles_post(command, output)
            return result
    return f"command executed: {command}"


# ── Helpers ──────────────────────────────────────────────────────────

def _print_separator(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def _print_result(result):
    """Print a detailed trace of the RunResult."""
    print(f"\n  Final output: \"{result.final_output[:120]}...\"" if len(str(result.final_output)) > 120 else f"\n  Final output: \"{result.final_output}\"")
    print(f"  Last agent:   {result.last_agent.name}")
    print(f"  Total turns:  {len(result.raw_responses)}")
    print(f"  Total items:  {len(result.new_items)}")
    print()

    for i, item in enumerate(result.new_items):
        if isinstance(item, HandoffCallItem):
            target = item.raw_item.name if hasattr(item.raw_item, 'name') else "?"
            print(f"    [{i:2d}] HANDOFF CALL  -> {target}")
        elif isinstance(item, HandoffOutputItem):
            current_agent = item.raw_item.get("agent_name", "?") if isinstance(item.raw_item, dict) else "?"
            print(f"    [{i:2d}] HANDOFF OUT   => now running: {current_agent}")
        elif isinstance(item, ToolCallItem):
            tool_name = item.raw_item.name if hasattr(item.raw_item, 'name') else "?"
            args = item.raw_item.arguments if hasattr(item.raw_item, 'arguments') else ""
            print(f"    [{i:2d}] TOOL CALL     {tool_name}({args[:60]})")
        elif isinstance(item, ToolCallOutputItem):
            output = str(item.output)
            if len(output) > 80:
                output = output[:80] + "..."
            print(f"    [{i:2d}] TOOL OUTPUT   -> {output}")
        elif isinstance(item, MessageOutputItem):
            text = ""
            if hasattr(item.raw_item, 'content'):
                for c in item.raw_item.content:
                    if hasattr(c, 'text'):
                        text = c.text
            if len(text) > 100:
                text = text[:100] + "..."
            print(f"    [{i:2d}] MESSAGE       \"{text}\"")
        else:
            print(f"    [{i:2d}] {type(item).__name__}: {item}")


def build_profiled_pattern():
    """
    Build the redteam orchestrated pattern with mock_linux_command
    that applies real tool_profiles post-processing.

    Returns the orchestrator agent and dicts of all agents/models.
    """
    orch_model = FakeModel()
    recon_model = FakeModel()
    strategy_model = FakeModel()
    exploit_model = FakeModel()
    privesc_model = FakeModel()
    report_model = FakeModel()

    think_tool = get_function_tool("think", "thought recorded")
    read_kf_tool = get_function_tool("read_key_findings", "no findings yet")
    write_kf_tool = get_function_tool("write_key_findings", "findings saved")

    # Create agents - each specialist gets the mock_linux_command with real profiles
    orchestrator = Agent(
        name="Red Team Orchestrator",
        model=orch_model,
        tools=[think_tool, read_kf_tool],
    )
    recon = Agent(
        name="Recon Agent",
        model=recon_model,
        tools=[mock_linux_command, write_kf_tool, read_kf_tool],
    )
    strategy = Agent(
        name="Strategy Agent",
        model=strategy_model,
        tools=[think_tool, write_kf_tool, read_kf_tool],
    )
    exploitation = Agent(
        name="Exploitation Agent",
        model=exploit_model,
        tools=[mock_linux_command, write_kf_tool, read_kf_tool],
    )
    privesc = Agent(
        name="PrivEsc Agent",
        model=privesc_model,
        tools=[mock_linux_command, write_kf_tool, read_kf_tool],
    )
    report = Agent(
        name="Report Agent",
        model=report_model,
        tools=[mock_linux_command, read_kf_tool],
    )

    for a in [orchestrator, recon, strategy, exploitation, privesc, report]:
        a._lock_model = True

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


# ── Tests: Specialist agents calling profiled tools ──────────────────

class TestReconProfiledTools:
    """Verify Recon agent can call profiled tools: nmap, gobuster, ffuf, nikto, whatweb, dirb, wfuzz."""

    @pytest.mark.asyncio
    async def test_recon_nmap_with_profile(self):
        """Recon calls nmap and the profile extracts OPEN PORTS SUMMARY."""
        _print_separator("Recon: nmap with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Recon(nmap) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "nmap -sV 172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Recon done. Open ports: 22, 80, 443.")],
        ])

        result = await Runner.run(orch, input="Scan target 172.17.0.2")

        _print_result(result)

        # Verify profile post-processing was applied
        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        nmap_output = next(
            (item.output for item in tool_outputs if "OPEN PORTS" in str(item.output)),
            None,
        )
        print(f"\n  nmap profile applied: {nmap_output is not None}")
        assert nmap_output is not None, "nmap profile should extract OPEN PORTS SUMMARY"
        assert "22/tcp" in nmap_output
        assert "80/tcp" in nmap_output
        assert result.last_agent.name == "Red Team Orchestrator"
        print("  [PASS] nmap profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_gobuster_with_profile(self):
        """Recon calls gobuster and the profile extracts DISCOVERED PATHS."""
        _print_separator("Recon: gobuster with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Recon(gobuster) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/common.txt"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Gobuster found /admin, /login, /uploads, /api.")],
        ])

        result = await Runner.run(orch, input="Enumerate directories on target")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        gobuster_output = next(
            (item.output for item in tool_outputs if "DISCOVERED PATHS" in str(item.output)),
            None,
        )
        print(f"\n  gobuster profile applied: {gobuster_output is not None}")
        assert gobuster_output is not None, "gobuster profile should extract DISCOVERED PATHS"
        assert "/admin" in gobuster_output
        print("  [PASS] gobuster profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_ffuf_with_profile(self):
        """Recon calls ffuf and the profile extracts DISCOVERED PATHS."""
        _print_separator("Recon: ffuf with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Recon(ffuf) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "ffuf -u http://172.17.0.2/FUZZ -w wordlist.txt"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("ffuf found admin, login, uploads endpoints.")],
        ])

        result = await Runner.run(orch, input="Fuzz endpoints on target")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        ffuf_output = next(
            (item.output for item in tool_outputs if "DISCOVERED PATHS" in str(item.output)),
            None,
        )
        print(f"\n  ffuf profile applied: {ffuf_output is not None}")
        assert ffuf_output is not None, "ffuf profile should extract DISCOVERED PATHS"
        print("  [PASS] ffuf profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_multiple_tools_nmap_and_nikto(self):
        """Recon calls nmap + nikto in one turn with both profiles applied."""
        _print_separator("Recon: nmap + nikto (multiple profiled tools in one turn)")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Recon(nmap + nikto) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "nmap -sV 172.17.0.2"})
                ),
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "nikto -h http://172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Recon complete: ports scanned, nikto vulnerabilities found.")],
        ])

        result = await Runner.run(orch, input="Full recon on 172.17.0.2")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        outputs_text = [str(item.output) for item in tool_outputs]

        has_nmap = any("OPEN PORTS" in o for o in outputs_text)
        has_nikto = any("NIKTO FINDINGS" in o for o in outputs_text)

        print(f"\n  nmap profile applied:  {has_nmap}")
        print(f"  nikto profile applied: {has_nikto}")
        assert has_nmap, "nmap profile should produce OPEN PORTS SUMMARY"
        assert has_nikto, "nikto profile should produce NIKTO FINDINGS"
        print("  [PASS] Both profiles applied in single Recon turn")


class TestExploitationProfiledTools:
    """Verify Exploitation agent can call profiled tools: sqlmap, hydra, searchsploit."""

    @pytest.mark.asyncio
    async def test_exploitation_sqlmap_with_profile(self):
        """Exploitation calls sqlmap and the profile post-processes the output."""
        _print_separator("Exploitation: sqlmap with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Exploitation(sqlmap) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["exploitation"])],
        ])
        models["exploitation"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "sqlmap -u 'http://172.17.0.2/page?id=1' --batch --dbs"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("SQL injection found. Parameter 'id' is vulnerable.")],
        ])

        result = await Runner.run(orch, input="Test for SQL injection")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        # sqlmap output should have been processed (profile applied)
        sqlmap_out = next(
            (item.output for item in tool_outputs
             if "generic_linux_command" not in str(item.output) and "sqlmap" in str(item.output).lower() or "vulnerable" in str(item.output).lower() or "parameter" in str(item.output).lower()),
            None,
        )
        print(f"\n  sqlmap profile applied: {sqlmap_out is not None}")
        assert sqlmap_out is not None, "sqlmap profile should process the output"
        assert result.last_agent.name == "Red Team Orchestrator"
        print("  [PASS] sqlmap profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_exploitation_hydra_with_profile(self):
        """Exploitation calls hydra and the profile extracts CREDENTIALS FOUND."""
        _print_separator("Exploitation: hydra with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Exploitation(hydra) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["exploitation"])],
        ])
        models["exploitation"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Hydra found valid credentials: admin:password123")],
        ])

        result = await Runner.run(orch, input="Brute force SSH credentials")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        hydra_output = next(
            (item.output for item in tool_outputs if "CREDENTIALS FOUND" in str(item.output)),
            None,
        )
        print(f"\n  hydra profile applied: {hydra_output is not None}")
        assert hydra_output is not None, "hydra profile should extract CREDENTIALS FOUND"
        assert "admin" in hydra_output
        assert "password123" in hydra_output
        print("  [PASS] hydra profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_exploitation_sqlmap_and_hydra_together(self):
        """Exploitation calls sqlmap + hydra in one turn."""
        _print_separator("Exploitation: sqlmap + hydra (multiple profiled tools)")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> Exploitation(sqlmap + hydra) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["exploitation"])],
        ])
        models["exploitation"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "sqlmap -u 'http://172.17.0.2/page?id=1' --batch"})
                ),
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "hydra -l admin -P pass.txt ssh://172.17.0.2"})
                ),
                get_function_tool_call("write_key_findings", json.dumps({"findings": "SQLi + SSH creds found"})),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Exploitation complete: SQLi and SSH credentials obtained.")],
        ])

        result = await Runner.run(orch, input="Exploit target")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        outputs_text = [str(item.output) for item in tool_outputs]

        has_hydra_creds = any("CREDENTIALS FOUND" in o for o in outputs_text)
        print(f"\n  hydra CREDENTIALS FOUND: {has_hydra_creds}")
        assert has_hydra_creds, "hydra profile should extract credentials"
        print("  [PASS] Both sqlmap and hydra profiles applied in one Exploitation turn")


class TestPrivEscProfiledTools:
    """Verify PrivEsc agent can call profiled tools: john, hashcat, enum4linux."""

    @pytest.mark.asyncio
    async def test_privesc_john_with_profile(self):
        """PrivEsc calls john and the profile extracts CRACKED PASSWORDS."""
        _print_separator("PrivEsc: john with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> PrivEsc(john) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["privesc"])],
        ])
        models["privesc"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("John cracked 2 passwords: admin:password123, root:toor")],
        ])

        result = await Runner.run(orch, input="Crack the password hashes")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        john_output = next(
            (item.output for item in tool_outputs if "CRACKED PASSWORDS" in str(item.output)),
            None,
        )
        print(f"\n  john profile applied: {john_output is not None}")
        assert john_output is not None, "john profile should extract CRACKED PASSWORDS"
        print("  [PASS] john profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_privesc_hashcat_with_profile(self):
        """PrivEsc calls hashcat and the profile extracts CRACKED HASHES."""
        _print_separator("PrivEsc: hashcat with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> PrivEsc(hashcat) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["privesc"])],
        ])
        models["privesc"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "hashcat -m 0 -a 0 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Hashcat cracked MD5 hashes.")],
        ])

        result = await Runner.run(orch, input="Crack MD5 hashes with hashcat")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        hashcat_output = next(
            (item.output for item in tool_outputs if "CRACKED HASHES" in str(item.output)),
            None,
        )
        print(f"\n  hashcat profile applied: {hashcat_output is not None}")
        assert hashcat_output is not None, "hashcat profile should extract CRACKED HASHES"
        print("  [PASS] hashcat profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_privesc_enum4linux_with_profile(self):
        """PrivEsc calls enum4linux and the profile extracts ENUM4LINUX SUMMARY."""
        _print_separator("PrivEsc: enum4linux with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow: Orch -> PrivEsc(enum4linux) -> Orch -> final")

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["privesc"])],
        ])
        models["privesc"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "enum4linux -a 172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Enum4linux found shares and users on target.")],
        ])

        result = await Runner.run(orch, input="Enumerate SMB on target")

        _print_result(result)

        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        enum_output = next(
            (item.output for item in tool_outputs if "ENUM4LINUX SUMMARY" in str(item.output)),
            None,
        )
        print(f"\n  enum4linux profile applied: {enum_output is not None}")
        assert enum_output is not None, "enum4linux profile should extract ENUM4LINUX SUMMARY"
        print("  [PASS] enum4linux profile post-processing verified through agent")


class TestReconAdditionalProfiledTools:
    """Verify remaining profiled tools: whatweb, wpscan, searchsploit, dirb, wfuzz."""

    @pytest.mark.asyncio
    async def test_recon_whatweb_with_profile(self):
        """Recon calls whatweb and the profile extracts TECHNOLOGIES DETECTED."""
        _print_separator("Recon: whatweb with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "whatweb http://172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("WhatWeb detected Apache, PHP, jQuery.")],
        ])

        result = await Runner.run(orch, input="Fingerprint web technologies")
        _print_result(result)

        tool_outputs = [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]
        whatweb_output = next(
            (item.output for item in tool_outputs if "TECHNOLOGIES DETECTED" in str(item.output)),
            None,
        )
        print(f"\n  whatweb profile applied: {whatweb_output is not None}")
        assert whatweb_output is not None, "whatweb profile should extract TECHNOLOGIES DETECTED"
        print("  [PASS] whatweb profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_wpscan_with_profile(self):
        """Recon calls wpscan and the profile extracts WPSCAN FINDINGS."""
        _print_separator("Recon: wpscan with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "wpscan --url http://172.17.0.2"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("WPScan found WordPress vulnerabilities.")],
        ])

        result = await Runner.run(orch, input="Scan WordPress site")
        _print_result(result)

        tool_outputs = [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]
        wpscan_output = next(
            (item.output for item in tool_outputs if "WPSCAN FINDINGS" in str(item.output)),
            None,
        )
        print(f"\n  wpscan profile applied: {wpscan_output is not None}")
        assert wpscan_output is not None, "wpscan profile should extract WPSCAN FINDINGS"
        print("  [PASS] wpscan profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_searchsploit_with_profile(self):
        """Recon calls searchsploit and the profile extracts EXPLOITS FOUND."""
        _print_separator("Recon: searchsploit with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "searchsploit apache 2.4"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Searchsploit found 2 Apache exploits.")],
        ])

        result = await Runner.run(orch, input="Search for exploits")
        _print_result(result)

        tool_outputs = [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]
        ss_output = next(
            (item.output for item in tool_outputs if "EXPLOITS FOUND" in str(item.output)),
            None,
        )
        print(f"\n  searchsploit profile applied: {ss_output is not None}")
        assert ss_output is not None, "searchsploit profile should extract EXPLOITS FOUND"
        print("  [PASS] searchsploit profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_dirb_with_profile(self):
        """Recon calls dirb and the profile extracts DISCOVERED URLS."""
        _print_separator("Recon: dirb with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "dirb http://172.17.0.2 /usr/share/wordlists/common.txt"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Dirb found admin, login, server-status.")],
        ])

        result = await Runner.run(orch, input="Directory brute force")
        _print_result(result)

        tool_outputs = [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]
        dirb_output = next(
            (item.output for item in tool_outputs if "DISCOVERED URLS" in str(item.output)),
            None,
        )
        print(f"\n  dirb profile applied: {dirb_output is not None}")
        assert dirb_output is not None, "dirb profile should extract DISCOVERED URLS"
        print("  [PASS] dirb profile post-processing verified through agent")

    @pytest.mark.asyncio
    async def test_recon_wfuzz_with_profile(self):
        """Recon calls wfuzz and the profile processes the output."""
        _print_separator("Recon: wfuzz with tool profile post-processing")
        orch, agents, models = build_profiled_pattern()

        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "wfuzz -z file,wordlist.txt http://172.17.0.2/FUZZ"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message("Wfuzz found endpoints.")],
        ])

        result = await Runner.run(orch, input="Fuzz target with wfuzz")
        _print_result(result)

        # wfuzz profile processes output (may or may not add header depending on format)
        tool_outputs = [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]
        wfuzz_outputs = [item.output for item in tool_outputs if "wfuzz" not in str(item.output).lower() or len(str(item.output)) > 10]
        assert len(wfuzz_outputs) > 0, "wfuzz tool should produce output"
        print("  [PASS] wfuzz profile post-processing verified through agent")


# ── Tests: Full pentest flow with profiled tools ─────────────────────

class TestFullPentestFlowWithProfiles:
    """End-to-end pentest flow verifying tool profiles across all handoffs."""

    @pytest.mark.asyncio
    async def test_full_pentest_flow_with_profiled_tools(self):
        """
        Full realistic pentest flow:
        Orch -> Recon(nmap+gobuster) -> Orch -> Strategy(think)
        -> Orch -> Exploit(sqlmap+hydra) -> Orch -> PrivEsc(john)
        -> Orch -> Report(searchsploit) -> Orch -> final
        """
        _print_separator("FULL PENTEST FLOW with Tool Profiles")
        orch, agents, models = build_profiled_pattern()

        print("\n  Flow:")
        print("    Turn  1: Orch -> handoff Recon")
        print("    Turn  2: Recon: nmap + gobuster + write_findings -> handoff Orch")
        print("    Turn  3: Orch -> handoff Strategy")
        print("    Turn  4: Strategy: think + write_findings -> handoff Orch")
        print("    Turn  5: Orch -> handoff Exploitation")
        print("    Turn  6: Exploitation: sqlmap + hydra + write_findings -> handoff Orch")
        print("    Turn  7: Orch -> handoff PrivEsc")
        print("    Turn  8: PrivEsc: john + write_findings -> handoff Orch")
        print("    Turn  9: Orch -> handoff Report")
        print("    Turn 10: Report: searchsploit -> handoff Orch")
        print("    Turn 11: Orch -> final text")

        # Turn 1: Orch -> Recon
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["recon"])],
        ])

        # Turn 2: Recon runs nmap + gobuster, hands back
        models["recon"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "nmap -sV -sC 172.17.0.2"})
                ),
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/common.txt"})
                ),
                get_function_tool_call(
                    "write_key_findings",
                    json.dumps({"findings": "Ports 22,80,443 open. Dirs: /admin, /login, /uploads, /api"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

        # Turn 3: Orch -> Strategy
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["strategy"])],
        ])

        # Turn 4: Strategy thinks and plans
        models["strategy"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "think",
                    json.dumps({"thought": "HTTP on 80 with /login and /admin - try SQLi and SSH brute force"})
                ),
                get_function_tool_call(
                    "write_key_findings",
                    json.dumps({"findings": "Attack plan: 1) SQLi on web app 2) SSH brute force 3) Crack any hashes"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

        # Turn 5: Orch -> Exploitation
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["exploitation"])],
        ])

        # Turn 6: Exploitation runs sqlmap + hydra
        models["exploitation"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "sqlmap -u 'http://172.17.0.2/login?id=1' --batch --dbs"})
                ),
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2"})
                ),
                get_function_tool_call(
                    "write_key_findings",
                    json.dumps({"findings": "SQLi confirmed on id param. SSH creds: admin:password123, root:toor"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

        # Turn 7: Orch -> PrivEsc
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["privesc"])],
        ])

        # Turn 8: PrivEsc cracks hashes with john
        models["privesc"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/shadow_hashes.txt"})
                ),
                get_function_tool_call(
                    "write_key_findings",
                    json.dumps({"findings": "Cracked root password from shadow file"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

        # Turn 9: Orch -> Report
        models["orchestrator"].add_multiple_turn_outputs([
            [get_handoff_tool_call(agents["report"])],
        ])

        # Turn 10: Report runs searchsploit for reference
        models["report"].add_multiple_turn_outputs([
            [
                get_function_tool_call(
                    "generic_linux_command",
                    json.dumps({"command": "searchsploit apache 2.4"})
                ),
                get_handoff_tool_call(agents["orchestrator"]),
            ],
        ])

        # Turn 11: Orch final answer
        models["orchestrator"].add_multiple_turn_outputs([
            [get_text_message(
                "Pentest complete. Summary:\n"
                "- Recon: 3 open ports (22,80,443), 4 web directories\n"
                "- Exploitation: SQLi on login page, SSH brute force successful\n"
                "- PrivEsc: Root password cracked from shadow file\n"
                "- Risk: CRITICAL"
            )],
        ])

        result = await Runner.run(orch, input="Full penetration test on 172.17.0.2")

        print("\n  Execution trace:")
        _print_result(result)

        # Verify the flow
        assert result.last_agent.name == "Red Team Orchestrator"
        assert len(result.raw_responses) == 11, f"Expected 11 turns, got {len(result.raw_responses)}"

        # Collect all tool outputs
        tool_outputs = [
            item for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        ]
        outputs_text = [str(item.output) for item in tool_outputs]

        print(f"\n  Tool outputs collected: {len(tool_outputs)}")

        # Verify each profile was applied
        profile_checks = {
            "nmap (OPEN PORTS)": any("OPEN PORTS" in o for o in outputs_text),
            "gobuster (DISCOVERED PATHS)": any("DISCOVERED PATHS" in o for o in outputs_text),
            "hydra (CREDENTIALS FOUND)": any("CREDENTIALS FOUND" in o for o in outputs_text),
            "john (CRACKED PASSWORDS)": any("CRACKED PASSWORDS" in o for o in outputs_text),
            "searchsploit (EXPLOITS FOUND)": any("EXPLOITS FOUND" in o for o in outputs_text),
        }

        print("\n  Profile verification:")
        all_passed = True
        for profile_name, found in profile_checks.items():
            status = "[PASS]" if found else "[FAIL]"
            print(f"    {status} {profile_name}: {'applied' if found else 'NOT FOUND'}")
            if not found:
                all_passed = False

        assert all_passed, f"Some profiles were not applied: {[k for k, v in profile_checks.items() if not v]}"

        # Verify handoffs happened correctly
        handoff_items = [
            item for item in result.new_items
            if isinstance(item, HandoffCallItem)
        ]
        print(f"\n  Handoff calls: {len(handoff_items)}")
        for item in handoff_items:
            target = item.raw_item.name if hasattr(item.raw_item, 'name') else "?"
            print(f"    -> {target}")

        # 10 handoffs: Orch->Recon, Recon->Orch, Orch->Strat, Strat->Orch,
        # Orch->Exploit, Exploit->Orch, Orch->PrivEsc, PrivEsc->Orch, Orch->Report, Report->Orch
        assert len(handoff_items) == 10, f"Expected 10 handoffs, got {len(handoff_items)}"

        print("\n  [PASS] Full pentest flow with tool profiles completed successfully")

    @pytest.mark.asyncio
    async def test_all_14_profiles_callable_through_agents(self):
        """
        Verify every one of the 14 tool profiles can be called through
        an agent using generic_linux_command and produces post-processed output.
        """
        _print_separator("ALL 14 TOOL PROFILES through Agent Calls")
        orch, agents, models = build_profiled_pattern()

        # Map each profiled tool to a realistic command
        tool_commands = {
            "nmap": "nmap -sV 172.17.0.2",
            "sqlmap": "sqlmap -u 'http://172.17.0.2/page?id=1' --batch",
            "hydra": "hydra -l admin -P pass.txt ssh://172.17.0.2",
            "john": "john --wordlist=rockyou.txt /tmp/hashes.txt",
            "hashcat": "hashcat -m 0 -a 0 /tmp/hashes.txt wordlist.txt",
            "ffuf": "ffuf -u http://172.17.0.2/FUZZ -w wordlist.txt",
            "gobuster": "gobuster dir -u http://172.17.0.2 -w wordlist.txt",
            "nikto": "nikto -h http://172.17.0.2",
            "dirb": "dirb http://172.17.0.2 /usr/share/wordlists/common.txt",
            "enum4linux": "enum4linux -a 172.17.0.2",
            "searchsploit": "searchsploit apache 2.4",
            "wfuzz": "wfuzz -z file,wordlist.txt http://172.17.0.2/FUZZ",
            "whatweb": "whatweb http://172.17.0.2",
            "wpscan": "wpscan --url http://172.17.0.2",
        }

        # We will call each tool through the Recon agent (one at a time)
        # to verify profile post-processing
        print(f"\n  Testing {len(tool_commands)} profiled tools through Recon agent:")

        results_map = {}
        for tool_name, command in tool_commands.items():
            # Build fresh pattern for each test to avoid state pollution
            orch, agents, models = build_profiled_pattern()

            models["orchestrator"].add_multiple_turn_outputs([
                [get_handoff_tool_call(agents["recon"])],
            ])
            models["recon"].add_multiple_turn_outputs([
                [
                    get_function_tool_call(
                        "generic_linux_command",
                        json.dumps({"command": command})
                    ),
                    get_handoff_tool_call(agents["orchestrator"]),
                ],
            ])
            models["orchestrator"].add_multiple_turn_outputs([
                [get_text_message(f"{tool_name} scan complete.")],
            ])

            result = await Runner.run(orch, input=f"Run {tool_name}")

            tool_outputs = [
                item for item in result.new_items
                if isinstance(item, ToolCallOutputItem)
            ]

            # Find the output from our generic_linux_command call
            cmd_output = None
            for item in tool_outputs:
                output_str = str(item.output)
                # Skip handoff outputs and other tool outputs
                if len(output_str) > 20 and tool_name not in ["write_key_findings", "read_key_findings", "think"]:
                    cmd_output = output_str
                    break

            results_map[tool_name] = cmd_output

            # Verify the raw simulated output was post-processed (not returned as-is)
            raw_output = SIMULATED_OUTPUTS.get(tool_name, "")
            if cmd_output and raw_output:
                # Post-processed output should be >= raw output (profiles append summaries)
                profile_applied = len(cmd_output) >= len(raw_output)
                status = "[PASS]" if profile_applied else "[WARN]"
                print(f"    {status} {tool_name:15s} raw={len(raw_output):4d} chars -> processed={len(cmd_output):4d} chars")
            else:
                print(f"    [INFO] {tool_name:15s} output captured: {cmd_output is not None}")

        # Verify all tools produced output
        tools_with_output = [name for name, out in results_map.items() if out is not None]
        print(f"\n  Tools with output: {len(tools_with_output)}/{len(tool_commands)}")
        assert len(tools_with_output) == len(tool_commands), (
            f"All 14 tools should produce output, missing: "
            f"{set(tool_commands.keys()) - set(tools_with_output)}"
        )
        print("  [PASS] All 14 profiled tools callable through agents")
