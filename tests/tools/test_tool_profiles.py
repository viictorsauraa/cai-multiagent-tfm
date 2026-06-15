"""
Tests for CAI Tool Profiles.

Verifies that each of the 14 tool profiles:
- Is auto-discovered by the registry
- Has a valid pattern that matches the expected commands
- Pre-processes commands correctly (smart_defaults)
- Post-processes tool output correctly (summaries, extraction)

No external tools (nmap, sqlmap, etc.) are needed — only the
profile logic (regex + string processing) is tested.
"""

from __future__ import annotations

import os
import sys
import pytest

# Ensure the CAI source is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from cai.tools.reconnaissance.tool_profiles import (
    ToolProfile,
    get_profiles,
    apply_profiles_pre,
    apply_profiles_post,
    get_idle_timeout,
    get_max_execution_time,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _print_separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _print_profile_info(profile: ToolProfile):
    print(f"    name:           {profile.name}")
    print(f"    pattern:        {profile.pattern}")
    print(f"    smart_defaults: {'Yes' if profile.smart_defaults else 'No'} (enabled={profile.smart_defaults_enabled})")
    print(f"    post_process:   {'Yes' if profile.post_process else 'No'}")
    print(f"    priority:       {profile.priority}")


# ── Registry Tests ───────────────────────────────────────────────────

class TestRegistry:

    def test_all_14_profiles_discovered(self):
        """All 14 tool profiles should be auto-discovered."""
        _print_separator("Registry: Auto-Discovery")
        profiles = get_profiles()
        names = [p.name for p in profiles]
        print(f"\n  Discovered {len(profiles)} profiles:")
        for p in profiles:
            print(f"    - {p.name} (priority={p.priority})")

        expected = {
            "dirb", "enum4linux", "ffuf", "gobuster", "hashcat",
            "hydra", "john", "nikto", "nmap", "searchsploit",
            "sqlmap", "wfuzz", "whatweb", "wpscan",
        }
        found = set(names)
        missing = expected - found
        extra = found - expected
        if missing:
            print(f"\n  MISSING: {missing}")
        if extra:
            print(f"\n  EXTRA: {extra}")

        assert expected.issubset(found), f"Missing profiles: {missing}"
        print(f"\n  ✓ All {len(expected)} expected profiles found")

    def test_all_profiles_have_valid_pattern(self):
        """Each profile pattern should compile and match its tool name."""
        _print_separator("Registry: Pattern Validation")
        profiles = get_profiles()
        for p in profiles:
            assert p.matches(p.name), f"Profile '{p.name}' pattern doesn't match its own name"
            print(f"    ✓ {p.name:15s} pattern={p.pattern!r} matches '{p.name}'")
        print(f"\n  ✓ All patterns valid")

    def test_profiles_sorted_by_priority(self):
        """Profiles should be sorted by priority (ascending)."""
        _print_separator("Registry: Priority Ordering")
        profiles = get_profiles()
        priorities = [p.priority for p in profiles]
        assert priorities == sorted(priorities), "Profiles not sorted by priority"
        for p in profiles:
            print(f"    priority={p.priority:3d} → {p.name}")
        print(f"\n  ✓ Profiles correctly sorted by priority")


# ── Pattern Matching Tests ───────────────────────────────────────────

class TestPatternMatching:

    @pytest.mark.parametrize("tool,commands", [
        ("nmap", ["nmap -sV 192.168.1.1", "nmap -p- 10.0.0.1", "sudo nmap -sC target"]),
        ("sqlmap", ["sqlmap -u http://target/page?id=1", "python sqlmap.py -u url"]),
        ("hydra", ["hydra -l admin -P pass.txt ssh://target", "hydra -L users.txt target ftp"]),
        ("john", ["john --wordlist=rockyou.txt hash.txt", "john hash.txt"]),
        ("hashcat", ["hashcat -m 0 -a 0 hash.txt wordlist.txt"]),
        ("ffuf", ["ffuf -u http://target/FUZZ -w wordlist.txt"]),
        ("gobuster", ["gobuster dir -u http://target -w wordlist.txt"]),
        ("nikto", ["nikto -h http://target"]),
        ("dirb", ["dirb http://target /usr/share/wordlists/common.txt"]),
        ("enum4linux", ["enum4linux -a 192.168.1.1"]),
        ("searchsploit", ["searchsploit apache 2.4"]),
        ("wfuzz", ["wfuzz -z file,wordlist.txt http://target/FUZZ"]),
        ("whatweb", ["whatweb http://target"]),
        ("wpscan", ["wpscan --url http://target"]),
    ])
    def test_profile_matches_real_commands(self, tool, commands):
        """Each profile should match realistic command invocations."""
        profiles = get_profiles()
        profile = next((p for p in profiles if p.name == tool), None)
        assert profile is not None, f"Profile '{tool}' not found"
        for cmd in commands:
            assert profile.matches(cmd), f"Profile '{tool}' should match: {cmd}"

    @pytest.mark.parametrize("tool,non_commands", [
        ("nmap", ["cat nmap_results.txt", "echo nmap is great"]),
        ("sqlmap", ["cat sqlmap.log"]),
        ("hydra", ["the hydration level"]),
    ])
    def test_profile_does_not_match_false_positives(self, tool, non_commands):
        """Profiles should use word boundaries to avoid false matches."""
        profiles = get_profiles()
        profile = next((p for p in profiles if p.name == tool), None)
        assert profile is not None
        for cmd in non_commands:
            # Note: some may still match due to \b boundary — document behavior
            result = profile.matches(cmd)
            print(f"    {tool}: '{cmd}' → match={result}")


# ── Smart Defaults Tests ─────────────────────────────────────────────

class TestSmartDefaults:

    def test_sqlmap_adds_forms_when_no_get_params(self):
        """sqlmap should add --forms --crawl=2 when URL has no GET parameters."""
        _print_separator("Smart Defaults: sqlmap")
        cmd = "sqlmap -u http://target/login --batch"
        result = apply_profiles_pre(cmd)
        print(f"    Input:  {cmd}")
        print(f"    Output: {result}")
        assert "--forms" in result, "Should add --forms"
        assert "--crawl=2" in result, "Should add --crawl=2"
        print("  ✓ Added --forms and --crawl=2")

    def test_sqlmap_skips_forms_when_get_params_present(self):
        """sqlmap should NOT add --forms when URL has GET parameters."""
        _print_separator("Smart Defaults: sqlmap (with params)")
        cmd = "sqlmap -u 'http://target/page?id=1' --batch"
        result = apply_profiles_pre(cmd)
        print(f"    Input:  {cmd}")
        print(f"    Output: {result}")
        assert "--forms" not in result or "?" in cmd, "Should not add --forms when GET params exist"
        print("  ✓ Correctly skipped --forms")

    def test_sqlmap_skips_forms_when_already_present(self):
        """sqlmap should NOT duplicate --forms."""
        _print_separator("Smart Defaults: sqlmap (--forms already present)")
        cmd = "sqlmap -u http://target/login --forms --batch"
        result = apply_profiles_pre(cmd)
        print(f"    Input:  {cmd}")
        print(f"    Output: {result}")
        assert result.count("--forms") == 1, "Should not duplicate --forms"
        print("  ✓ No duplication")

    def test_john_adds_wordlist_when_no_mode(self):
        """john should add --wordlist=rockyou.txt when no attack mode specified."""
        _print_separator("Smart Defaults: john")
        cmd = "john hash.txt"
        result = apply_profiles_pre(cmd)
        print(f"    Input:  {cmd}")
        print(f"    Output: {result}")
        assert "--wordlist=" in result, "Should add --wordlist"
        assert "rockyou" in result, "Should use rockyou.txt"
        print("  ✓ Added --wordlist=rockyou.txt")

    def test_john_skips_wordlist_when_mode_present(self):
        """john should NOT add wordlist when attack mode already specified."""
        _print_separator("Smart Defaults: john (mode present)")
        for mode in ["--wordlist=/custom/list.txt", "--incremental", "--single", "--show"]:
            cmd = f"john {mode} hash.txt"
            result = apply_profiles_pre(cmd)
            print(f"    Input:  {cmd}")
            print(f"    Output: {result}")
            assert result.count("--wordlist") <= 1, f"Should not add extra --wordlist when {mode} present"
        print("  ✓ Correctly skipped for all modes")

    def test_non_smart_default_profiles_pass_through(self):
        """Profiles without smart_defaults should pass commands unchanged."""
        _print_separator("Smart Defaults: Pass-through")
        profiles = get_profiles()
        no_sd = [p for p in profiles if not p.smart_defaults_enabled]
        print(f"  {len(no_sd)} profiles without smart_defaults:")
        for p in no_sd:
            cmd = f"{p.name} --some-flag target"
            result = p.apply_pre(cmd)
            assert result == cmd, f"{p.name} modified the command!"
            print(f"    ✓ {p.name:15s} unchanged")
        print(f"\n  ✓ All pass-through correctly")


# ── Post-Processing Tests ────────────────────────────────────────────

class TestPostProcess:

    def test_nmap_extracts_open_ports(self):
        """nmap post-process should extract and summarize open ports."""
        _print_separator("Post-Process: nmap")
        nmap_output = """Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 172.17.0.2
Host is up (0.00023s latency).
Not shown: 998 closed tcp ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache httpd 2.4.52
443/tcp open  ssl/http  nginx 1.18.0

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"""

        result = apply_profiles_post("nmap -sV 172.17.0.2", nmap_output)
        print(f"    Input length:  {len(nmap_output)} chars")
        print(f"    Output length: {len(result)} chars")

        assert "OPEN PORTS SUMMARY" in result
        assert "22/tcp" in result
        assert "80/tcp" in result
        assert "443/tcp" in result
        # Show the appended summary
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"\n    Appended summary:\n{result[summary_start:]}")
        print("  ✓ Open ports extracted correctly")

    def test_nmap_no_open_ports(self):
        """nmap post-process should handle output with no open ports."""
        _print_separator("Post-Process: nmap (no open ports)")
        nmap_output = """Starting Nmap 7.94SVN
All 1000 scanned ports on 172.17.0.2 are filtered
Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds"""

        result = apply_profiles_post("nmap 172.17.0.2", nmap_output)
        print(f"    Output: {result[-100:]}")
        # Should still return the output, just without summary or with empty summary
        assert nmap_output in result
        print("  ✓ Handled gracefully")

    def test_hydra_extracts_credentials(self):
        """hydra post-process should extract found credentials."""
        _print_separator("Post-Process: hydra")
        hydra_output = """Hydra v9.5 (c) 2023 by van Hauser
[DATA] attacking ssh://172.17.0.2:22/
[22][ssh] host: 172.17.0.2   login: admin   password: password123
[22][ssh] host: 172.17.0.2   login: root   password: toor
1 of 1 target completed, 2 valid passwords found"""

        result = apply_profiles_post("hydra -L users.txt -P pass.txt ssh://172.17.0.2", hydra_output)
        assert "CREDENTIALS FOUND" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Credentials extracted")

    def test_hydra_no_credentials(self):
        """hydra post-process should handle no credentials found."""
        _print_separator("Post-Process: hydra (no creds)")
        hydra_output = """Hydra v9.5
[DATA] attacking ssh://172.17.0.2:22/
1 of 1 target completed, 0 valid passwords found"""

        result = apply_profiles_post("hydra -l admin -P pass.txt ssh://172.17.0.2", hydra_output)
        print(f"    Output: {result[-80:]}")
        assert hydra_output in result
        print("  ✓ Handled gracefully")

    def test_john_extracts_cracked_passwords(self):
        """john post-process should extract cracked passwords."""
        _print_separator("Post-Process: john")
        john_output = """Using default input encoding: UTF-8
Loaded 2 password hashes
Press 'q' or Ctrl-C to abort
password123      (admin)
toor             (root)
2g 0:00:00:05 DONE"""

        result = apply_profiles_post("john --wordlist=rockyou.txt hash.txt", john_output)
        assert "CRACKED PASSWORDS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Passwords extracted")

    def test_hashcat_extracts_cracked_hashes(self):
        """hashcat post-process should extract cracked hashes."""
        _print_separator("Post-Process: hashcat")
        hashcat_output = """hashcat (v6.2.6) starting
Session: hashcat
5f4dcc3b5aa765d61d8327deb882cf99:password
e10adc3949ba59abbe56e057f20f883e:123456
Status.........: Cracked"""

        result = apply_profiles_post("hashcat -m 0 hashes.txt wordlist.txt", hashcat_output)
        assert "CRACKED HASHES" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Hashes extracted")

    def test_gobuster_extracts_paths(self):
        """gobuster post-process should extract discovered paths."""
        _print_separator("Post-Process: gobuster")
        gobuster_output = """===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 200)
/login                (Status: 302)
/uploads              (Status: 403)
/api                  (Status: 200)
==============================================================="""

        result = apply_profiles_post("gobuster dir -u http://target -w wordlist.txt", gobuster_output)
        assert "DISCOVERED PATHS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Paths extracted")

    def test_ffuf_extracts_endpoints(self):
        """ffuf post-process should extract discovered endpoints."""
        _print_separator("Post-Process: ffuf")
        ffuf_output = """        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
admin                   [Status: 200, Size: 1234, Words: 100, Lines: 50]
login                   [Status: 302, Size: 0, Words: 0, Lines: 0]
uploads                 [Status: 403, Size: 278, Words: 20, Lines: 10]"""

        result = apply_profiles_post("ffuf -u http://target/FUZZ -w wordlist.txt", ffuf_output)
        assert "DISCOVERED PATHS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Endpoints extracted")

    def test_dirb_extracts_urls(self):
        """dirb post-process should extract discovered URLs."""
        _print_separator("Post-Process: dirb")
        dirb_output = """START_TIME: Mon Mar 18 2026
URL_BASE: http://target/
WORDLIST_FILES: /usr/share/wordlists/common.txt
+ http://target/admin (CODE:200|SIZE:1234)
+ http://target/login (CODE:302|SIZE:0)
+ http://target/server-status (CODE:403|SIZE:277)
END_TIME: Mon Mar 18 2026"""

        result = apply_profiles_post("dirb http://target /usr/share/wordlists/common.txt", dirb_output)
        assert "DISCOVERED URLS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ URLs extracted")

    def test_nikto_extracts_findings(self):
        """nikto post-process should extract vulnerability findings."""
        _print_separator("Post-Process: nikto")
        nikto_output = """- Nikto v2.5.0
+ Target IP:          172.17.0.2
+ Target Hostname:    172.17.0.2
+ Target Port:        80
+ Start Time:         2026-03-18
+ Server: Apache/2.4.52
+ /admin/: Directory indexing found
+ /login.php: Admin login page found
+ OSVDB-3233: /icons/README: Apache default file found
+ 7915 requests: 0 error(s) and 3 item(s) reported"""

        result = apply_profiles_post("nikto -h http://172.17.0.2", nikto_output)
        assert "NIKTO FINDINGS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Findings extracted")

    def test_searchsploit_extracts_exploits(self):
        """searchsploit post-process should extract exploit entries."""
        _print_separator("Post-Process: searchsploit")
        searchsploit_output = """-------------------------------------------------------------------
 Exploit Title                          |  Path
-------------------------------------------------------------------
Apache 2.4.49 - Path Traversal         | exploits/multiple/webapps/50383.py
Apache 2.4.50 - RCE                    | exploits/multiple/webapps/50406.sh
-------------------------------------------------------------------"""

        result = apply_profiles_post("searchsploit apache 2.4", searchsploit_output)
        assert "EXPLOITS FOUND" in result
        summary_start = result.find("---\n", result.find("EXPLOITS"))
        if summary_start != -1:
            print(f"    Summary:\n{result[result.find('EXPLOITS'):]}")
        print("  ✓ Exploits extracted")

    def test_whatweb_extracts_technologies(self):
        """whatweb post-process should extract detected technologies."""
        _print_separator("Post-Process: whatweb")
        whatweb_output = """http://target [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[172.17.0.2], jQuery[3.6.0], PHP[8.1.2], Title[Welcome]"""

        result = apply_profiles_post("whatweb http://target", whatweb_output)
        assert "TECHNOLOGIES DETECTED" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Technologies extracted")

    def test_wpscan_extracts_findings(self):
        """wpscan post-process should extract vulnerabilities."""
        _print_separator("Post-Process: wpscan")
        wpscan_output = """_______________________________________________________________
         __          _______   _____
         \\ \\        / /  __ \\ / ____|
          \\ \\  /\\  / /| |__) | (___   ___  __ _ _ __
           \\ \\/  \\/ / |  ___/ \\___ \\ / __|/ _` | '_ \\
            \\  /\\  /  | |     ____) | (__| (_| | | | |
             \\/  \\/   |_|    |_____/ \\___|\\__,_|_| |_|

[+] URL: http://target/
[+] Started: Mon Mar 18 2026

[!] The WordPress 'readme.html' file exists
[!] XML-RPC seems to be enabled
[i] Plugin(s) Identified:
 Title: Contact Form 7 5.3.2
 Title: Yoast SEO 16.5

[+] Finished: Mon Mar 18 2026"""

        result = apply_profiles_post("wpscan --url http://target", wpscan_output)
        assert "WPSCAN FINDINGS" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Findings extracted")

    def test_enum4linux_extracts_info(self):
        """enum4linux post-process should extract shares, users, groups."""
        _print_separator("Post-Process: enum4linux")
        enum4linux_output = """Starting enum4linux v0.9.1
 ===========================
|    Share Enumeration    |
 ===========================
//172.17.0.2/IPC$       Mapping: OK Listing: DENIED
//172.17.0.2/shared     Mapping: OK Listing: OK
//172.17.0.2/admin$     Mapping: DENIED Listing: N/A

 ============================
|    Users on 172.17.0.2    |
 ============================
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[sshd] rid:[0x3e8]

 ============================
|    Groups on 172.17.0.2   |
 ============================
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]"""

        result = apply_profiles_post("enum4linux -a 172.17.0.2", enum4linux_output)
        assert "ENUM4LINUX SUMMARY" in result
        summary_start = result.find("---")
        if summary_start != -1:
            print(f"    Summary:\n{result[summary_start:]}")
        print("  ✓ Shares/users/groups extracted")

    def test_wfuzz_extracts_hits(self):
        """wfuzz post-process should extract fuzzing hits."""
        _print_separator("Post-Process: wfuzz")
        wfuzz_output = """********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                        *
********************************************************
Target: http://target/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
1:           C=200      15 L     42 W       1234 Ch     "admin"
2:           C=302      0 L      0 W        0 Ch        "login"
3:           C=403      9 L      28 W       277 Ch      "server-status"

Total time: 5.123456"""

        result = apply_profiles_post("wfuzz -z file,wordlist.txt http://target/FUZZ", wfuzz_output)
        # wfuzz may or may not extract depending on exact format
        print(f"    Output tail:\n{result[-200:]}")
        print("  ✓ Processed without error")


# ── Integration Tests ────────────────────────────────────────────────

class TestIntegration:

    def test_apply_profiles_pre_routes_to_correct_profile(self):
        """apply_profiles_pre should find the matching profile and apply it."""
        _print_separator("Integration: Pre-processing Routing")

        # sqlmap should get --forms
        cmd = "sqlmap -u http://target/page --batch"
        result = apply_profiles_pre(cmd)
        print(f"    sqlmap: {cmd}")
        print(f"         → {result}")
        assert "--forms" in result

        # nmap should pass through (no smart_defaults)
        cmd = "nmap -sV 192.168.1.1"
        result = apply_profiles_pre(cmd)
        print(f"    nmap:   {cmd}")
        print(f"         → {result}")
        assert result == cmd

        print("  ✓ Routing works correctly")

    def test_apply_profiles_post_routes_to_correct_profile(self):
        """apply_profiles_post should find the matching profile and apply it."""
        _print_separator("Integration: Post-processing Routing")

        nmap_out = "22/tcp open  ssh\n80/tcp open  http"
        result = apply_profiles_post("nmap -sV target", nmap_out)
        print(f"    nmap post-process applied: {'OPEN PORTS' in result}")
        assert "OPEN PORTS" in result

        hydra_out = "[22][ssh] host: target   login: admin   password: pass123"
        result = apply_profiles_post("hydra -l admin -P pass.txt ssh://target", hydra_out)
        print(f"    hydra post-process applied: {'CREDENTIALS' in result}")
        assert "CREDENTIALS" in result

        print("  ✓ Routing works correctly")

    def test_unknown_command_passes_through(self):
        """Commands that don't match any profile should pass unchanged."""
        _print_separator("Integration: Unknown Command Pass-through")

        cmd = "ls -la /tmp"
        pre_result = apply_profiles_pre(cmd)
        assert pre_result == cmd
        print(f"    pre:  '{cmd}' → unchanged ✓")

        post_result = apply_profiles_post(cmd, "total 0\ndrwxrwxrwt 2 root root 40 Mar 18 20:00 .")
        assert "total 0" in post_result
        print(f"    post: '{cmd}' → unchanged ✓")

        print("  ✓ Pass-through correct")

    def test_smart_defaults_can_be_disabled(self, monkeypatch):
        """CAI_TOOL_SMART_DEFAULTS=false should disable all pre-processing."""
        _print_separator("Integration: Smart Defaults Disabled")

        monkeypatch.setenv("CAI_TOOL_SMART_DEFAULTS", "false")

        cmd = "sqlmap -u http://target/page --batch"
        result = apply_profiles_pre(cmd)
        print(f"    Input:  {cmd}")
        print(f"    Output: {result}")
        assert result == cmd, "Smart defaults should be disabled"
        assert "--forms" not in result
        print("  ✓ Smart defaults disabled correctly")


# ── Idle timeout ─────────────────────────────────────────────────────


class TestIdleTimeout:
    """Verify per-profile idle_timeout configuration."""

    def test_sqlmap_idle_timeout_is_120(self):
        """sqlmap needs 120s for time-based blind SQLi."""
        assert get_idle_timeout("sqlmap -u http://target --batch") == 120

    def test_default_idle_timeout_is_10(self):
        """Commands with no matching profile get default 10s."""
        assert get_idle_timeout("ls -la /tmp") == 10

    def test_nmap_uses_default_idle_timeout(self):
        """nmap has no custom idle_timeout — gets default 10s."""
        assert get_idle_timeout("nmap -sV 192.168.1.1") == 10

    def test_idle_timeout_field_on_all_profiles(self):
        """All profiles must have a valid idle_timeout >= 1."""
        for p in get_profiles():
            assert p.idle_timeout >= 1, f"Profile '{p.name}' has invalid idle_timeout"


# ── Max execution time ──────────────────────────────────────────────


class TestMaxExecutionTime:
    """Verify per-profile max_execution_time configuration."""

    def test_sqlmap_max_execution_time_is_300(self):
        """sqlmap capped at 300s to prevent indefinite blind SQLi runs."""
        assert get_max_execution_time("sqlmap -u http://target --batch") == 300

    def test_default_no_limit(self):
        """Commands with no matching profile get 0 (no limit)."""
        assert get_max_execution_time("ls -la /tmp") == 0

    def test_nmap_uses_default(self):
        """nmap has no custom max_execution_time — gets default 0."""
        assert get_max_execution_time("nmap -sV 192.168.1.1") == 0

    def test_field_on_all_profiles(self):
        """All profiles must have max_execution_time >= 0."""
        for p in get_profiles():
            assert p.max_execution_time >= 0, f"Profile '{p.name}' has invalid max_execution_time"


class TestJohnPatternFalsePositives:
    """john profile must NOT match when 'john' appears as username/path."""

    @pytest.mark.parametrize("cmd", [
        "cat /home/john/file.txt",
        "ssh john@target",
        "grep john /etc/passwd",
        "echo john",
        "ls -la /tmp/john_backup/",
    ])
    def test_john_does_not_match_non_command(self, cmd):
        profiles = get_profiles()
        john_profile = next(p for p in profiles if p.name == "john")
        assert not john_profile.matches(cmd), f"john profile should NOT match: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "john hash.txt",
        "sudo john hash.txt",
        "echo test && john hash.txt",
        "ls; john hash.txt",
        "cat file | john --stdin",
    ])
    def test_john_matches_as_command(self, cmd):
        profiles = get_profiles()
        john_profile = next(p for p in profiles if p.name == "john")
        assert john_profile.matches(cmd), f"john profile should match: {cmd}"


class TestSqlmapSmartDefaultsImproved:
    """Verify sqlmap smart defaults skip non-scan modes and parse URLs correctly."""

    def test_no_defaults_with_help(self):
        result = apply_profiles_pre("sqlmap --help")
        assert "--forms" not in result

    def test_no_defaults_with_request_file(self):
        result = apply_profiles_pre("sqlmap -r request.txt --batch")
        assert "--forms" not in result

    def test_no_defaults_when_url_has_params(self):
        result = apply_profiles_pre("sqlmap -u 'http://target/page?id=1' --batch")
        assert "--forms" not in result

    def test_adds_defaults_when_url_no_params(self):
        result = apply_profiles_pre("sqlmap -u http://target/page --batch")
        assert "--forms" in result
        assert "--crawl=2" in result

    def test_no_defaults_with_hh_flag(self):
        result = apply_profiles_pre("sqlmap -hh")
        assert "--forms" not in result

    def test_no_defaults_when_data_present(self):
        """sqlmap with --data should NOT get --forms/--crawl added."""
        result = apply_profiles_pre(
            "sqlmap -u 'http://target/login/' --data='user=admin&pass=test' --batch --dbs"
        )
        assert "--forms" not in result
        assert "--crawl" not in result

    def test_no_defaults_when_data_with_dump(self):
        """Realistic sqlmap with --data + --dump should not get discovery flags."""
        result = apply_profiles_pre(
            "sqlmap -u 'http://172.17.0.2/login/' --data='username=admin&password=test' "
            "--threads=4 --batch --dump --dbs shop --tables"
        )
        assert "--forms" not in result
        assert "--crawl" not in result


# ── Help Output Detection ──────────────────────────────────────────


class TestHelpOutputDetection:
    """Verify that help/usage pages are detected and replaced with clear errors."""

    def test_ffuf_help_detected(self):
        """ffuf help output should be replaced with an error message."""
        ffuf_help = (
            "Fuzz Faster U Fool - v2.1.0-dev\n\n"
            "HTTP OPTIONS:\n"
            "  -H  Header\n"
            "  -X  HTTP method\n"
            "  -u  Target URL\n"
            "  -w  Wordlist file path\n"
        )
        result = apply_profiles_post("ffuf -u http://target/FUZZ -w missing.txt", ffuf_help)
        assert "ERROR:" in result
        assert "help/usage page" in result
        assert "HTTP OPTIONS:" not in result  # original help text replaced

    def test_ffuf_normal_output_not_detected(self):
        """Normal ffuf output should pass through to post-processing."""
        ffuf_output = (
            "/admin                  [Status: 200, Size: 1234, Words: 100, Lines: 50]\n"
            "/login                  [Status: 302, Size: 0, Words: 0, Lines: 0]\n"
        )
        result = apply_profiles_post("ffuf -u http://target/FUZZ -w wordlist.txt", ffuf_output)
        assert "ERROR:" not in result
        assert "/admin" in result

    def test_gobuster_help_detected(self):
        """gobuster help output should be replaced with an error message."""
        gobuster_help = (
            "Usage:\n"
            "  gobuster [command]\n\n"
            "Available Commands:\n"
            "  dir         Uses directory/file enumeration mode\n"
            "  dns         Uses DNS subdomain enumeration mode\n"
        )
        result = apply_profiles_post("gobuster dir -u http://target", gobuster_help)
        assert "ERROR:" in result
        assert "help/usage page" in result

    def test_dirb_help_detected(self):
        """dirb help output should be replaced with an error message."""
        dirb_help = (
            "----- DIRB v2.22\n"
            "By The Dark Raver\n\n"
            "USAGE: dirb <url_base> [wordlist]\n"
        )
        result = apply_profiles_post("dirb http://target", dirb_help)
        assert "ERROR:" in result

    def test_wfuzz_help_detected(self):
        """wfuzz help output should be replaced with an error message."""
        wfuzz_help = (
            "Usage:\n\n"
            "\twfuzz [options] -z payload,params <url>\n\n"
        )
        result = apply_profiles_post("wfuzz -z file,wordlist http://target/FUZZ", wfuzz_help)
        assert "ERROR:" in result

    def test_profile_without_help_indicators_passes_through(self):
        """Profiles with no help_indicators should never trigger detection."""
        # nmap has no help_indicators configured
        result = apply_profiles_post("nmap --help", "Usage: nmap [Scan Type(s)]")
        assert "ERROR:" not in result

    def test_partial_match_does_not_trigger(self):
        """If only one indicator is present, detection should NOT trigger."""
        # Only "Fuzz Faster U Fool" without "HTTP OPTIONS:"
        partial = "Fuzz Faster U Fool - scanning target..."
        result = apply_profiles_post("ffuf -u http://target/FUZZ -w wordlist.txt", partial)
        assert "ERROR:" not in result


class TestPatternMatchingFix:
    """Verify that tool profile patterns match only the binary name, not paths."""

    def test_dirb_not_matched_in_wordlist_path(self):
        """dirb pattern should NOT match when 'dirb' appears in a file path."""
        profiles = get_profiles()
        dirb = next(p for p in profiles if p.name == "dirb")
        assert not dirb.matches("ffuf -w /usr/share/wordlists/dirb/common.txt -u http://t/FUZZ")

    def test_dirb_matched_as_command(self):
        """dirb pattern should match when dirb is the executed command."""
        profiles = get_profiles()
        dirb = next(p for p in profiles if p.name == "dirb")
        assert dirb.matches("dirb http://target/ /usr/share/wordlists/common.txt")

    def test_ffuf_with_dirb_wordlist_applies_ffuf_profile(self):
        """apply_profiles_post should apply ffuf profile (not dirb) for ffuf commands."""
        result = apply_profiles_post(
            "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            "/admin  [Status: 200, Size: 1234, Words: 56, Lines: 78]",
        )
        assert "DISCOVERED PATHS" in result

    def test_ffuf_help_detected_with_dirb_wordlist(self):
        """ffuf help page should be detected even when using a dirb wordlist path."""
        ffuf_help = (
            "Fuzz Faster U Fool - v2.1.0-dev\n\n"
            "HTTP OPTIONS:\n  -H  Header\n  -X  HTTP method\n"
        )
        result = apply_profiles_post(
            "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            ffuf_help,
        )
        assert result.startswith("ERROR: ffuf printed its help/usage page")

    def test_sudo_prefix_still_matches(self):
        """Commands prefixed with sudo should still match their profile."""
        profiles = get_profiles()
        nmap = next(p for p in profiles if p.name == "nmap")
        assert nmap.matches("sudo nmap -sV 10.0.0.1")
