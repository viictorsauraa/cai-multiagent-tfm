"""Tests for _try_extract_text_tool_call and its helper functions.

Covers all supported patterns for detecting tool calls and handoffs
written as plain text by smaller LLMs (qwen3:8b, llama3.3, etc.).
"""

import pytest

from cai.sdk.agents._run_impl import _try_extract_text_tool_call


# ── Fixtures ─────────────────────────────────────────────────────────


class _FakeTool:
    """Minimal stand-in for FunctionTool (only .name is read)."""
    def __init__(self, name: str):
        self.name = name


class _FakeHandoff:
    """Minimal stand-in for Handoff (tool_name + agent_name are read)."""
    def __init__(self, tool_name: str, agent_name: str):
        self.tool_name = tool_name
        self.agent_name = agent_name


@pytest.fixture
def function_map():
    return {
        "generic_linux_command": _FakeTool("generic_linux_command"),
        "write_key_findings": _FakeTool("write_key_findings"),
        "read_key_findings": _FakeTool("read_key_findings"),
        "execute_code": _FakeTool("execute_code"),
    }


@pytest.fixture
def handoff_map():
    return {
        "transfer_to_recon_agent": _FakeHandoff(
            "transfer_to_recon_agent", "Recon Agent"
        ),
        "transfer_to_strategy_agent": _FakeHandoff(
            "transfer_to_strategy_agent", "Strategy Agent"
        ),
        "transfer_to_red_team_orchestrator": _FakeHandoff(
            "transfer_to_red_team_orchestrator", "Red Team Orchestrator"
        ),
    }


# ── Pattern 1: Python-style function calls ───────────────────────────


class TestPythonStyleCalls:
    """Detect tool_name(...) written as plain text."""

    def test_handoff_no_args(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            "transfer_to_recon_agent()", function_map, handoff_map
        )
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_function_with_kwarg(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            'generic_linux_command(command="nmap -sV 10.0.0.1")',
            function_map,
            handoff_map,
        )
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params["command"] == "nmap -sV 10.0.0.1"
        assert kind == "function"

    def test_function_multiple_kwargs(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            'generic_linux_command(command="ls", timeout="30")',
            function_map,
            handoff_map,
        )
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params["command"] == "ls"
        assert params["timeout"] == "30"
        assert kind == "function"

    def test_llama3_python_tag(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            '<|python_tag|>transfer_to_recon_agent()',
            function_map,
            handoff_map,
        )
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_llama3_python_tag_with_args(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            '<|python_tag|>generic_linux_command(command="ls -la")',
            function_map,
            handoff_map,
        )
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params["command"] == "ls -la"
        assert kind == "function"

    def test_text_before_call(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            'I will scan the target: generic_linux_command(command="nmap 10.0.0.1")',
            function_map,
            handoff_map,
        )
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params["command"] == "nmap 10.0.0.1"
        assert kind == "function"

    def test_text_after_call(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            'transfer_to_recon_agent() to begin reconnaissance',
            function_map,
            handoff_map,
        )
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_empty_parens_function(self, function_map, handoff_map):
        result = _try_extract_text_tool_call(
            "read_key_findings()", function_map, handoff_map
        )
        assert result == ("read_key_findings", {}, "function")

    def test_case_insensitive_capitalized(self, function_map, handoff_map):
        """Capitalized tool name like Think(...) should match 'think'."""
        fn_map = {
            "think": _FakeTool("think"),
            **function_map,
        }
        result = _try_extract_text_tool_call(
            'Think(thought="analyzing the target")', fn_map, handoff_map
        )
        assert result is not None
        name, params, kind = result
        assert name == "think"
        assert params["thought"] == "analyzing the target"
        assert kind == "function"

    def test_case_insensitive_upper(self, function_map, handoff_map):
        """Fully uppercase tool name should match lowercase registered name."""
        result = _try_extract_text_tool_call(
            'GENERIC_LINUX_COMMAND(command="whoami")',
            function_map,
            handoff_map,
        )
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params["command"] == "whoami"
        assert kind == "function"

    def test_case_insensitive_mixed(self, function_map, handoff_map):
        """Mixed case tool name should match lowercase registered name."""
        result = _try_extract_text_tool_call(
            'Generic_Linux_Command(command="id")',
            function_map,
            handoff_map,
        )
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "id"}

    def test_case_insensitive_handoff(self, function_map, handoff_map):
        """Capitalized handoff name should match lowercase registered name."""
        result = _try_extract_text_tool_call(
            "Transfer_To_Recon_Agent()", function_map, handoff_map
        )
        assert result is not None
        assert result[0] == "transfer_to_recon_agent"
        assert result[2] == "handoff"


# ── Pattern 2: JSON objects ──────────────────────────────────────────


class TestJsonObjects:
    """Detect {"name": "tool", "parameters": {...}} in text."""

    def test_json_function_with_params(self, function_map, handoff_map):
        text = '{"name": "generic_linux_command", "parameters": {"command": "ls"}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params == {"command": "ls"}
        assert kind == "function"

    def test_json_handoff_empty_params(self, function_map, handoff_map):
        text = '{"name": "transfer_to_recon_agent", "parameters": {}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_json_arguments_key(self, function_map, handoff_map):
        """'arguments' key should work as well as 'parameters'."""
        text = '{"name": "transfer_to_recon_agent", "arguments": {}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_json_no_params_key(self, function_map, handoff_map):
        """Missing parameters/arguments should default to empty dict."""
        text = '{"name": "transfer_to_recon_agent"}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_json_embedded_in_text(self, function_map, handoff_map):
        text = 'I will call {"name": "generic_linux_command", "parameters": {"command": "whoami"}} now'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params == {"command": "whoami"}
        assert kind == "function"

    def test_json_nested_params(self, function_map, handoff_map):
        text = '{"name": "generic_linux_command", "parameters": {"command": "echo \\"{test}\\""}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[2] == "function"


# ── Pattern 3: Fuzzy handoff matching ────────────────────────────────


class TestFuzzyHandoff:
    """Detect invented names like 'delegate' with agent field."""

    def test_delegate_with_agent_param(self, function_map, handoff_map):
        text = '{"name": "delegate", "parameters": {"agent": "Recon Agent"}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_call_agent_with_agent_name_param(self, function_map, handoff_map):
        text = '{"name": "call_agent", "parameters": {"agent_name": "Recon Agent"}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_fuzzy_agent_in_root(self, function_map, handoff_map):
        """Agent name at root level of JSON (not in parameters)."""
        text = '{"name": "handoff", "agent": "Strategy Agent", "parameters": {}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_strategy_agent", {}, "handoff")

    def test_fuzzy_case_insensitive(self, function_map, handoff_map):
        text = '{"name": "delegate", "parameters": {"agent": "recon agent"}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result == ("transfer_to_recon_agent", {}, "handoff")

    def test_fuzzy_unknown_agent(self, function_map, handoff_map):
        """Agent name that doesn't match any known agent returns None."""
        text = '{"name": "delegate", "parameters": {"agent": "Unknown Agent"}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None


# ── Edge cases / no-match ────────────────────────────────────────────


class TestEdgeCases:
    """Inputs that should NOT match any pattern."""

    def test_empty_string(self, function_map, handoff_map):
        assert _try_extract_text_tool_call("", function_map, handoff_map) is None

    def test_none_text(self, function_map, handoff_map):
        # text="" is falsy, should return None
        assert _try_extract_text_tool_call("", function_map, handoff_map) is None

    def test_plain_text(self, function_map, handoff_map):
        assert _try_extract_text_tool_call(
            "I'm analyzing the target network for vulnerabilities",
            function_map,
            handoff_map,
        ) is None

    def test_json_without_name(self, function_map, handoff_map):
        assert _try_extract_text_tool_call(
            '{"key": "value"}', function_map, handoff_map
        ) is None

    def test_unknown_tool_name(self, function_map, handoff_map):
        assert _try_extract_text_tool_call(
            '{"name": "nonexistent_tool", "parameters": {}}',
            function_map,
            handoff_map,
        ) is None

    def test_unknown_function_call(self, function_map, handoff_map):
        assert _try_extract_text_tool_call(
            "unknown_function()", function_map, handoff_map
        ) is None

    def test_empty_maps(self, function_map, handoff_map):
        assert _try_extract_text_tool_call(
            "generic_linux_command()", {}, {}
        ) is None

    def test_no_handoff_map(self, function_map):
        """handoff_map=None should work (functions only)."""
        result = _try_extract_text_tool_call(
            'generic_linux_command(command="ls")', function_map, None
        )
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[2] == "function"

    def test_partial_name_no_match(self, function_map, handoff_map):
        """'generic_linux' without full name should not match."""
        assert _try_extract_text_tool_call(
            "generic_linux()", function_map, handoff_map
        ) is None

    def test_json_with_non_dict_params(self, function_map, handoff_map):
        """Parameters that are not a dict should not match."""
        assert _try_extract_text_tool_call(
            '{"name": "generic_linux_command", "parameters": "invalid"}',
            function_map,
            handoff_map,
        ) is None


# ── Priority: Python-style over JSON ─────────────────────────────────


class TestPriority:
    """Python-style detection should take priority over JSON."""

    def test_python_takes_priority(self, function_map, handoff_map):
        """When both patterns could match, Python-style wins."""
        text = 'generic_linux_command(command="ls") and also {"name": "read_key_findings", "parameters": {}}'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[2] == "function"


# ── Pattern 4: Raw commands in markdown code blocks ──────────────────


class TestCodeBlockDetection:
    """Detect raw commands inside ```bash / ```sh / ``` code blocks."""

    def test_bash_code_block(self, function_map, handoff_map):
        text = "Let's scan the target:\n```bash\nnmap -sV 10.0.0.1\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        name, params, kind = result
        assert name == "generic_linux_command"
        assert params == {"command": "nmap -sV 10.0.0.1"}
        assert kind == "function"

    def test_sh_code_block(self, function_map, handoff_map):
        text = "Execute:\n```sh\ncurl http://example.com\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "curl http://example.com"}

    def test_shell_code_block(self, function_map, handoff_map):
        text = "```shell\nwhoami\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "whoami"}

    def test_no_language_code_block(self, function_map, handoff_map):
        text = "Run this:\n```\nls -la /tmp\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "ls -la /tmp"}

    def test_multiline_code_block(self, function_map, handoff_map):
        text = "```bash\ncurl -v 'http://172.17.0.2/products/index.php' \\\n  --data-urlencode 'search=1 UNION SELECT 1,2,3'\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "curl" in result[1]["command"]
        assert "UNION SELECT" in result[1]["command"]

    def test_code_block_with_special_tokens(self, function_map, handoff_map):
        text = "<|im_start|>assistant\n```bash\nnmap -p 80 10.0.0.1\n```<|im_end|>"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "nmap -p 80 10.0.0.1"}

    def test_code_block_json_skipped(self, function_map, handoff_map):
        """JSON inside code blocks should not match (handled by JSON parser)."""
        text = '```\n{"name": "generic_linux_command", "parameters": {"command": "ls"}}\n```'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        # Should be caught by _try_json_object, not _try_code_block
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_code_block_no_generic_linux_command(self, handoff_map):
        """Code block detection requires generic_linux_command in function_map."""
        function_map_no_glc = {
            "write_key_findings": _FakeTool("write_key_findings"),
        }
        text = "```bash\nnmap 10.0.0.1\n```"
        result = _try_extract_text_tool_call(text, function_map_no_glc, handoff_map)
        assert result is None

    def test_python_style_priority_over_code_block(self, function_map, handoff_map):
        """Python-style detection takes priority over code block."""
        text = 'generic_linux_command(command="ls")\n```bash\nnmap 10.0.0.1\n```'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert result[1] == {"command": "ls"}

    # ── Prose rejection tests ──

    def test_prose_rejected_and_starter(self, function_map, handoff_map):
        """Prose starting with 'And' should be rejected."""
        text = "```bash\nAnd for information_schema we need to dump tables\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    def test_prose_rejected_lets(self, function_map, handoff_map):
        """Prose starting with 'Let's' should be rejected."""
        text = "```bash\nLet's try a different approach\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    def test_prose_rejected_the(self, function_map, handoff_map):
        """Prose starting with 'The' should be rejected."""
        text = "```\nThe next step is to enumerate the database.\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    def test_prose_rejected_multiline(self, function_map, handoff_map):
        """Multiple lines of prose should be rejected."""
        text = "```bash\nFirst we need to scan the target.\nThen we exploit the vulnerability.\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    # ── Command acceptance tests ──

    def test_command_with_flags_accepted(self, function_map, handoff_map):
        """Commands with flags should still be accepted."""
        text = "```bash\nnmap -sV -p 80,443 10.0.0.1\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_command_pipe_accepted(self, function_map, handoff_map):
        """Commands with pipes should still be accepted."""
        text = "```bash\ncat /etc/passwd | grep root\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_command_dotslash_accepted(self, function_map, handoff_map):
        """Relative path commands should still be accepted."""
        text = "```bash\n./exploit.sh\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_command_env_var_accepted(self, function_map, handoff_map):
        """Commands with env vars should still be accepted."""
        text = "```bash\nPYTHONPATH=/tmp python3 exploit.py\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_command_comment_then_cmd_accepted(self, function_map, handoff_map):
        """Shell comments followed by commands should be accepted."""
        text = "```bash\n# scan ports\nnmap 10.0.0.1\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"

    def test_only_comment_rejected(self, function_map, handoff_map):
        """A code block with only comments should be rejected."""
        text = "```bash\n# just a comment\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    # ── Cross-block matching fix ──

    def test_cross_block_prose_not_captured(self, function_map, handoff_map):
        """Prose between two ```sql blocks must NOT be captured (cross-block bug)."""
        text = (
            "For `shop`:\n"
            "```sql\nsqlmap -u 'http://target/login/' --dbs shop --tables\n```\n"
            "And for `information_schema` (if it contains any user-defined tables):\n"
            "```sql\nsqlmap -u 'http://target/login/' --dbs information_schema --tables\n```\n"
        )
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        # Should extract the first sqlmap command from the sql block, not the prose
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "sqlmap" in result[1]["command"]
        assert "And for" not in result[1]["command"]

    def test_dangerous_cross_block_not_captured(self, function_map, handoff_map):
        """Dangerous text between ```sql blocks must NOT be captured."""
        text = (
            "```sql\nSELECT * FROM users\n```\n"
            "rm -rf /tmp/danger\n"
            "```sql\nSELECT * FROM orders\n```\n"
        )
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        # Should NOT capture 'rm -rf /tmp/danger'
        if result is not None:
            assert "rm -rf" not in result[1].get("command", "")

    def test_bash_block_after_sql_blocks(self, function_map, handoff_map):
        """A ```bash block after ```sql blocks should be extracted correctly."""
        text = (
            "```sql\nSELECT 1\n```\n"
            "Now let's scan:\n"
            "```bash\nnmap -sV 10.0.0.1\n```\n"
        )
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        # Could extract from sql or bash block, but must NOT extract prose
        assert "Now let" not in result[1]["command"]

    # ── All-block capture tests ──

    def test_sql_block_extracted(self, function_map, handoff_map):
        """Commands in ```sql blocks should now be extracted."""
        text = "```sql\nsqlmap -u 'http://target/' --batch --dump\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "sqlmap" in result[1]["command"]

    def test_python_block_with_shell_command(self, function_map, handoff_map):
        """Shell commands in ```python blocks should be extracted."""
        text = "```python\npython3 exploit.py --target 10.0.0.1\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "python3" in result[1]["command"]

    # ── Shell construct acceptance tests ──

    def test_for_loop_accepted(self, function_map, handoff_map):
        """Shell for loops should be accepted despite 'for' being a prose starter."""
        text = "```bash\nfor i in $(seq 1 10); do echo $i; done\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "for i in" in result[1]["command"]

    def test_if_bracket_accepted(self, function_map, handoff_map):
        """Shell if statements should be accepted despite 'if' being a prose starter."""
        text = "```bash\nif [ -f /etc/passwd ]; then cat /etc/passwd; fi\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "if [" in result[1]["command"]

    def test_while_true_accepted(self, function_map, handoff_map):
        """Shell while loops should be accepted despite 'while' being a prose starter."""
        text = "```bash\nwhile true; do ping -c1 10.0.0.1; sleep 1; done\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "generic_linux_command"
        assert "while true" in result[1]["command"]

    def test_for_prose_still_rejected(self, function_map, handoff_map):
        """English prose starting with 'For' (not a shell for loop) should be rejected."""
        text = "```bash\nFor each database, enumerate all tables and columns.\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    def test_if_prose_still_rejected(self, function_map, handoff_map):
        """English prose starting with 'If' (not a shell if statement) should be rejected."""
        text = "```bash\nIf the target is vulnerable, try the exploit.\n```"
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None


# ── Substring false-positive prevention ──────────────────────────────


class TestSubstringFalsePositives:
    """Tool name substring matches must not trigger false positives."""

    def test_no_substring_match_prefix(self, handoff_map):
        """'execute_code(' should not match when text has 'pre_execute_code('."""
        function_map = {
            "execute_code": _FakeTool("execute_code"),
        }
        text = 'pre_execute_code(command="ls")'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is None

    def test_no_substring_match_longer_name(self, handoff_map):
        """If tools 'scan' and 'port_scan' exist, 'port_scan(...)' must not match 'scan'."""
        function_map = {
            "scan": _FakeTool("scan"),
            "port_scan": _FakeTool("port_scan"),
        }
        text = 'port_scan(target="10.0.0.1")'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "port_scan"

    def test_exact_match_still_works(self, handoff_map):
        """Exact tool name at start of text should still match."""
        function_map = {
            "scan": _FakeTool("scan"),
        }
        text = 'scan(target="10.0.0.1")'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[0] == "scan"


# ── Numeric and unquoted argument parsing ────────────────────────────


class TestNumericArgsParsing:
    """_parse_args should capture unquoted values (numbers, booleans)."""

    def test_numeric_arg(self, function_map, handoff_map):
        text = 'generic_linux_command(command="nmap", port=8080)'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[1].get("port") == "8080"

    def test_boolean_arg(self, function_map, handoff_map):
        text = 'generic_linux_command(command="test", verbose=True)'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[1].get("verbose") == "True"

    def test_mixed_quoted_and_unquoted(self, function_map, handoff_map):
        text = 'generic_linux_command(command="nmap -sV", timeout=120)'
        result = _try_extract_text_tool_call(text, function_map, handoff_map)
        assert result is not None
        assert result[1].get("command") == "nmap -sV"
        assert result[1].get("timeout") == "120"
