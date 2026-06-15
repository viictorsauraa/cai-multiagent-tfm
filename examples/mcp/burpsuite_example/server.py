"""
Burp Suite MCP Server for CAI.

MCP server that wraps Burp Suite's REST API, exposing scanning,
spidering, and issue retrieval as tools that any MCP-compatible
LLM client (including CAI) can use.

Requirements:
    - Burp Suite Professional running with the REST API extension
      (https://github.com/vmware/burp-rest-api) on http://localhost:1337
      OR Burp Suite with the built-in REST API (v2024+)
    - pip install mcp[server] requests

Usage:
    # Start the MCP server (SSE transport, default port 8000)
    python server.py

    # Then in CAI:
    /mcp load http://localhost:8000/sse burp
    /mcp add burp <agent_name>
"""

import os
import time
from typing import Optional

import requests
from mcp.server.fastmcp import FastMCP

# ── Configuration ────────────────────────────────────────────────────
BURP_API_URL = os.getenv("BURP_API_URL", "http://localhost:1337")
BURP_API_KEY = os.getenv("BURP_API_KEY", "")

mcp = FastMCP("Burp Suite")


def _headers() -> dict:
    """Build request headers with optional API key."""
    h = {"Content-Type": "application/json"}
    if BURP_API_KEY:
        h["Authorization"] = f"Bearer {BURP_API_KEY}"
    return h


def _api(method: str, path: str, **kwargs) -> requests.Response:
    """Make a request to the Burp REST API."""
    url = f"{BURP_API_URL}{path}"
    return requests.request(method, url, headers=_headers(), timeout=30, **kwargs)


# ── Tools ────────────────────────────────────────────────────────────

@mcp.tool()
def burp_scan(target_url: str, scan_type: str = "active") -> str:
    """
    Launch a Burp Suite scan against a target URL.

    Args:
        target_url: The URL to scan (e.g. http://target.com)
        scan_type: Type of scan - 'active' (default) or 'passive'

    Returns:
        Scan task ID and status message.
    """
    print(f"[burp-mcp] Starting {scan_type} scan on {target_url}")
    payload = {
        "urls": [target_url],
        "scan_configurations": [
            {"type": "NamedConfiguration", "name": f"Audit checks - {scan_type}"}
        ],
    }

    try:
        resp = _api("POST", "/v0.1/scan", json=payload)
        if resp.status_code in (200, 201):
            task_id = resp.headers.get("Location", resp.text).strip("/").split("/")[-1]
            return f"Scan launched successfully. Task ID: {task_id}"
        return f"Error launching scan: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return (
            f"Cannot connect to Burp Suite at {BURP_API_URL}. "
            "Ensure Burp is running with the REST API extension enabled."
        )


@mcp.tool()
def burp_scan_status(task_id: str) -> str:
    """
    Check the status of a running Burp Suite scan.

    Args:
        task_id: The scan task ID returned by burp_scan.

    Returns:
        Current scan status including progress percentage.
    """
    print(f"[burp-mcp] Checking scan status for task {task_id}")
    try:
        resp = _api("GET", f"/v0.1/scan/{task_id}")
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("scan_status", "unknown")
            metrics = data.get("scan_metrics", {})
            progress = metrics.get("crawl_and_audit_progress", "N/A")
            items = metrics.get("audit_items_count", "N/A")
            return (
                f"Scan {task_id}: {status}\n"
                f"Progress: {progress}%\n"
                f"Audit items: {items}"
            )
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_get_issues(target_url: Optional[str] = None) -> str:
    """
    Retrieve issues (vulnerabilities) found by Burp Suite.

    Args:
        target_url: Optional filter - only show issues for this URL.
                    If not provided, returns all issues.

    Returns:
        Formatted list of discovered vulnerabilities with severity.
    """
    print(f"[burp-mcp] Getting issues for {target_url or 'all targets'}")
    try:
        resp = _api("GET", "/v0.1/kb/issues")
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code} - {resp.text}"

        issues = resp.json().get("issues", resp.json() if isinstance(resp.json(), list) else [])

        if target_url:
            issues = [
                i for i in issues
                if target_url in i.get("origin", "") or target_url in i.get("url", "")
            ]

        if not issues:
            return "No issues found." + (f" (filtered by {target_url})" if target_url else "")

        lines = [f"Found {len(issues)} issue(s):\n"]
        for i, issue in enumerate(issues, 1):
            severity = issue.get("severity", "unknown")
            confidence = issue.get("confidence", "unknown")
            name = issue.get("name", issue.get("issue_type_name", "Unknown"))
            url = issue.get("url", issue.get("origin", "N/A"))
            lines.append(
                f"  [{i}] [{severity.upper()}] {name}\n"
                f"      URL: {url}\n"
                f"      Confidence: {confidence}"
            )

        return "\n".join(lines)
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_get_issue_details(issue_index: int, target_url: Optional[str] = None) -> str:
    """
    Get detailed information about a specific issue including request/response.

    Args:
        issue_index: Issue number from burp_get_issues output (1-based).
        target_url: Optional filter to match the same filter used in burp_get_issues.

    Returns:
        Detailed issue information including description, remediation, and evidence.
    """
    print(f"[burp-mcp] Getting issue details for #{issue_index}")
    try:
        resp = _api("GET", "/v0.1/kb/issues")
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code}"

        issues = resp.json().get("issues", resp.json() if isinstance(resp.json(), list) else [])
        if target_url:
            issues = [
                i for i in issues
                if target_url in i.get("origin", "") or target_url in i.get("url", "")
            ]

        if issue_index < 1 or issue_index > len(issues):
            return f"Invalid index. Use 1-{len(issues)}."

        issue = issues[issue_index - 1]
        parts = [
            f"Issue: {issue.get('name', issue.get('issue_type_name', 'Unknown'))}",
            f"Severity: {issue.get('severity', 'N/A')}",
            f"Confidence: {issue.get('confidence', 'N/A')}",
            f"URL: {issue.get('url', issue.get('origin', 'N/A'))}",
            f"Path: {issue.get('path', 'N/A')}",
        ]

        if issue.get("description"):
            parts.append(f"\nDescription:\n{issue['description']}")
        if issue.get("remediation"):
            parts.append(f"\nRemediation:\n{issue['remediation']}")
        if issue.get("vulnerability_classifications"):
            parts.append(f"\nClassifications: {issue['vulnerability_classifications']}")

        evidence = issue.get("evidence", [])
        if evidence:
            parts.append(f"\nEvidence ({len(evidence)} item(s)):")
            for j, ev in enumerate(evidence, 1):
                req = ev.get("request_response", {})
                if req.get("request"):
                    req_preview = req["request"][:500]
                    parts.append(f"  [{j}] Request:\n{req_preview}")
                if req.get("response"):
                    resp_preview = req["response"][:500]
                    parts.append(f"  [{j}] Response:\n{resp_preview}")

        return "\n".join(parts)
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_spider(target_url: str) -> str:
    """
    Start Burp Suite spider/crawler on a target URL to discover content.

    Args:
        target_url: The base URL to spider (e.g. http://target.com).

    Returns:
        Status message about the spidering task.
    """
    print(f"[burp-mcp] Spidering {target_url}")
    payload = {
        "urls": [target_url],
        "scan_configurations": [
            {"type": "NamedConfiguration", "name": "Crawl strategy - fastest"}
        ],
    }

    try:
        resp = _api("POST", "/v0.1/scan", json=payload)
        if resp.status_code in (200, 201):
            task_id = resp.headers.get("Location", resp.text).strip("/").split("/")[-1]
            return f"Spider/crawl launched. Task ID: {task_id}"
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_sitemap(url_prefix: Optional[str] = None) -> str:
    """
    Retrieve the sitemap (discovered URLs) from Burp Suite.

    Args:
        url_prefix: Optional URL prefix to filter results.
                    If not provided, returns the full sitemap.

    Returns:
        List of discovered URLs in the sitemap.
    """
    print(f"[burp-mcp] Getting sitemap for {url_prefix or 'all'}")
    try:
        params = {}
        if url_prefix:
            params["urlPrefix"] = url_prefix
        resp = _api("GET", "/v0.1/sitemap", params=params)
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code} - {resp.text}"

        data = resp.json()
        urls = set()
        items = data if isinstance(data, list) else data.get("items", [])
        for item in items:
            url = item.get("url") or item.get("host", "")
            if url:
                urls.add(url)

        if not urls:
            return "Sitemap is empty. Run burp_spider first."

        sorted_urls = sorted(urls)
        return (
            f"Sitemap ({len(sorted_urls)} URLs):\n"
            + "\n".join(f"  {u}" for u in sorted_urls)
        )
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_proxy_history(limit: int = 20) -> str:
    """
    Retrieve recent entries from Burp Suite's proxy history.

    Args:
        limit: Maximum number of entries to return (default: 20).

    Returns:
        Formatted list of recent proxied requests.
    """
    print(f"[burp-mcp] Getting proxy history (limit={limit})")
    try:
        resp = _api("GET", "/v0.1/proxy/history")
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code} - {resp.text}"

        data = resp.json()
        entries = data if isinstance(data, list) else data.get("items", [])
        entries = entries[-limit:]

        if not entries:
            return "Proxy history is empty."

        lines = [f"Proxy history (last {len(entries)} entries):\n"]
        for i, entry in enumerate(entries, 1):
            method = entry.get("method", "?")
            url = entry.get("url", entry.get("host", "N/A"))
            status = entry.get("status_code", entry.get("response_status", "?"))
            length = entry.get("response_length", "?")
            lines.append(f"  [{i}] {method:6s} {status} {url} ({length} bytes)")

        return "\n".join(lines)
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_send_to_repeater(
    method: str, url: str, headers: str = "", body: str = ""
) -> str:
    """
    Send a request to Burp Suite's Repeater tool for manual testing.

    Args:
        method: HTTP method (GET, POST, PUT, etc.).
        url: Target URL.
        headers: Raw HTTP headers (one per line, e.g. "Host: target.com\\nCookie: x=1").
        body: Request body (for POST/PUT).

    Returns:
        Status message confirming the request was sent.
    """
    print(f"[burp-mcp] Sending {method} {url} to Repeater")
    header_lines = headers.split("\\n") if headers else []
    raw_request = f"{method} {url} HTTP/1.1\r\n"
    for h in header_lines:
        raw_request += f"{h}\r\n"
    raw_request += f"\r\n{body}"

    payload = {"request": raw_request, "url": url}

    try:
        resp = _api("POST", "/v0.1/repeater", json=payload)
        if resp.status_code in (200, 201, 204):
            return f"Request sent to Repeater: {method} {url}"
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_scope_check(url: str) -> str:
    """
    Check if a URL is in Burp Suite's target scope.

    Args:
        url: URL to check.

    Returns:
        Whether the URL is in scope or not.
    """
    print(f"[burp-mcp] Checking scope for {url}")
    try:
        resp = _api("GET", "/v0.1/target/scope", params={"url": url})
        if resp.status_code == 200:
            data = resp.json()
            in_scope = data.get("in_scope", data) if isinstance(data, dict) else data
            return f"{url} is {'IN' if in_scope else 'OUT OF'} scope."
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


@mcp.tool()
def burp_add_to_scope(url: str) -> str:
    """
    Add a URL to Burp Suite's target scope.

    Args:
        url: URL to add to scope (e.g. http://target.com).

    Returns:
        Confirmation message.
    """
    print(f"[burp-mcp] Adding {url} to scope")
    try:
        resp = _api("PUT", "/v0.1/target/scope", json={"url": url})
        if resp.status_code in (200, 204):
            return f"Added {url} to Burp scope."
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to Burp Suite at {BURP_API_URL}."


if __name__ == "__main__":
    mcp.run(transport="sse")
