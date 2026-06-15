"""
OWASP ZAP MCP Server for CAI.

MCP server that wraps OWASP ZAP's REST API, exposing scanning,
spidering, and alert retrieval as tools that any MCP-compatible
LLM client (including CAI) can use.

Requirements:
    - OWASP ZAP running with API enabled (default port 8080)
      Start with: zaproxy -daemon -port 8080 -config api.disablekey=true
      Or with API key: zaproxy -daemon -port 8080
    - pip install "mcp[server]" requests

Usage:
    # Start the MCP server (SSE transport, default port 8000)
    python server.py

    # Then in CAI:
    /mcp load http://localhost:8000/sse zap
    /mcp add zap <agent_name>
"""

import os
from typing import Optional

import requests
from mcp.server.fastmcp import FastMCP

# ── Configuration ────────────────────────────────────────────────────
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

mcp = FastMCP("OWASP ZAP")


def _api(method: str, path: str, **kwargs) -> requests.Response:
    """Make a request to the ZAP REST API."""
    url = f"{ZAP_API_URL}{path}"
    params = kwargs.pop("params", {})
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    return requests.request(method, url, params=params, timeout=30, **kwargs)


def _check_connection() -> Optional[str]:
    """Check if ZAP is reachable. Returns error message or None."""
    try:
        resp = _api("GET", "/JSON/core/view/version/")
        if resp.status_code == 200:
            return None
        return f"ZAP returned HTTP {resp.status_code}"
    except requests.ConnectionError:
        return (
            f"Cannot connect to ZAP at {ZAP_API_URL}. "
            "Start ZAP with: zaproxy -daemon -port 8080 -config api.disablekey=true"
        )


# ── Tools ────────────────────────────────────────────────────────────

@mcp.tool()
def zap_scan(target_url: str | int, scan_type: str | int = "active") -> str:
    """
    Launch a ZAP scan against a target URL.

    Args:
        target_url: The URL to scan (e.g. http://target.com).
        scan_type: Type of scan - 'active' (default) or 'passive'.

    Returns:
        Scan ID and status message.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url)
    scan_type = str(scan_type).lower()
    try:
        if scan_type == "passive":
            # Passive scan is automatic when spidering, just check alerts
            return (
                "Passive scanning is automatic in ZAP. "
                "Run zap_spider first, then check zap_get_alerts for passive findings."
            )

        # Active scan
        resp = _api("GET", "/JSON/ascan/action/scan/", params={
            "url": target_url,
            "recurse": "true",
            "inScopeOnly": "false",
        })
        if resp.status_code == 200:
            data = resp.json()
            scan_id = data.get("scan", "unknown")
            return f"Active scan launched. Scan ID: {scan_id}\nUse zap_scan_status(scan_id='{scan_id}') to check progress."
        return f"Error launching scan: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_scan_status(scan_id: int | str) -> str:
    """
    Check the status of a running ZAP active scan.

    Args:
        scan_id: The scan ID returned by zap_scan (accepts int or string).

    Returns:
        Current scan progress percentage.
    """
    err = _check_connection()
    if err:
        return err

    scan_id = str(scan_id)
    try:
        resp = _api("GET", "/JSON/ascan/view/status/", params={"scanId": scan_id})
        if resp.status_code == 200:
            data = resp.json()
            progress = data.get("status", "unknown")
            return f"Scan {scan_id}: {progress}% complete"
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_spider(target_url: str | int, max_depth: int | str = 5) -> str:
    """
    Start ZAP spider/crawler on a target URL to discover content.

    Args:
        target_url: The base URL to spider (e.g. http://target.com).
        max_depth: Maximum crawl depth (default: 5, accepts int or string).

    Returns:
        Spider scan ID and status message.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url)
    try:
        max_depth = int(max_depth)
    except (TypeError, ValueError):
        max_depth = 5

    try:
        resp = _api("GET", "/JSON/spider/action/scan/", params={
            "url": target_url,
            "maxchildren": "0",
            "recurse": "true",
            "subtreeonly": "false",
        })
        if resp.status_code == 200:
            data = resp.json()
            scan_id = data.get("scan", "unknown")
            return f"Spider launched. Scan ID: {scan_id}\nUse zap_spider_status(scan_id='{scan_id}') to check progress."
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_spider_status(scan_id: int | str) -> str:
    """
    Check the status of a running ZAP spider.

    Args:
        scan_id: The spider scan ID returned by zap_spider (accepts int or string).

    Returns:
        Current spider progress percentage.
    """
    err = _check_connection()
    if err:
        return err

    scan_id = str(scan_id)
    try:
        resp = _api("GET", "/JSON/spider/view/status/", params={"scanId": scan_id})
        if resp.status_code == 200:
            data = resp.json()
            progress = data.get("status", "unknown")
            return f"Spider {scan_id}: {progress}% complete"
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_get_alerts(
    target_url: Optional[str | int] = None,
    risk_level: Optional[str | int] = None,
) -> str:
    """
    Retrieve alerts (vulnerabilities) found by ZAP.

    Args:
        target_url: Optional filter - only show alerts for this base URL.
        risk_level: Optional filter by risk: 'High', 'Medium', 'Low', 'Informational'.

    Returns:
        Formatted list of discovered vulnerabilities with risk level.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url) if target_url is not None else None
    risk_level = str(risk_level) if risk_level is not None else None

    try:
        params = {"start": "0", "count": "100"}
        if target_url:
            params["baseurl"] = target_url

        resp = _api("GET", "/JSON/alert/view/alerts/", params=params)
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code} - {resp.text}"

        alerts = resp.json().get("alerts", [])

        if risk_level:
            alerts = [a for a in alerts if a.get("risk", "").lower() == risk_level.lower()]

        if not alerts:
            return "No alerts found." + (f" (filtered by {target_url})" if target_url else "")

        lines = [f"Found {len(alerts)} alert(s):\n"]
        for i, alert in enumerate(alerts, 1):
            risk = alert.get("risk", "unknown")
            confidence = alert.get("confidence", "unknown")
            name = alert.get("name", alert.get("alert", "Unknown"))
            url = alert.get("url", "N/A")
            lines.append(
                f"  [{i}] [{risk.upper()}] {name}\n"
                f"      URL: {url}\n"
                f"      Confidence: {confidence}"
            )

        return "\n".join(lines)
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_get_alert_details(alert_id: int | str) -> str:
    """
    Get detailed information about a specific alert.

    Args:
        alert_id: Alert ID from the 'id' field in zap_get_alerts output
            (accepts int or string).

    Returns:
        Detailed alert information including description, solution, and evidence.
    """
    err = _check_connection()
    if err:
        return err

    alert_id = str(alert_id)
    try:
        resp = _api("GET", "/JSON/alert/view/alert/", params={"id": alert_id})
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code}"

        alert = resp.json().get("alert", {})
        parts = [
            f"Alert: {alert.get('name', alert.get('alert', 'Unknown'))}",
            f"Risk: {alert.get('risk', 'N/A')}",
            f"Confidence: {alert.get('confidence', 'N/A')}",
            f"URL: {alert.get('url', 'N/A')}",
            f"Method: {alert.get('method', 'N/A')}",
            f"Parameter: {alert.get('param', 'N/A')}",
            f"Attack: {alert.get('attack', 'N/A')}",
            f"Evidence: {alert.get('evidence', 'N/A')}",
            f"CWE ID: {alert.get('cweid', 'N/A')}",
            f"WASC ID: {alert.get('wascid', 'N/A')}",
        ]

        if alert.get("description"):
            parts.append(f"\nDescription:\n{alert['description']}")
        if alert.get("solution"):
            parts.append(f"\nSolution:\n{alert['solution']}")
        if alert.get("reference"):
            parts.append(f"\nReferences:\n{alert['reference']}")
        if alert.get("other"):
            parts.append(f"\nOther info:\n{alert['other']}")

        return "\n".join(parts)
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_sitemap(url_prefix: Optional[str | int] = None) -> str:
    """
    Retrieve discovered URLs from ZAP's site tree.

    Args:
        url_prefix: Optional URL prefix to filter (e.g. http://target.com).

    Returns:
        List of discovered URLs.
    """
    err = _check_connection()
    if err:
        return err

    url_prefix = str(url_prefix) if url_prefix is not None else None

    try:
        resp = _api("GET", "/JSON/core/view/sites/")
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code} - {resp.text}"

        sites = resp.json().get("sites", [])

        if not sites:
            return "No sites discovered. Run zap_spider first."

        if url_prefix:
            sites = [s for s in sites if url_prefix in s]

        # Get URLs for each site
        all_urls = []
        for site in sites:
            resp2 = _api("GET", "/JSON/core/view/urls/", params={"baseurl": site})
            if resp2.status_code == 200:
                urls = resp2.json().get("urls", [])
                all_urls.extend(urls)

        if not all_urls:
            return f"Sites found: {', '.join(sites)}\nNo URLs in site tree yet. Run zap_spider first."

        return (
            f"Sitemap ({len(all_urls)} URLs):\n"
            + "\n".join(f"  {u}" for u in sorted(set(all_urls))[:100])
        )
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_ajax_spider(target_url: str | int) -> str:
    """
    Start ZAP's AJAX spider for JavaScript-heavy applications.
    More thorough than regular spider for modern web apps.

    Args:
        target_url: The URL to crawl with the AJAX spider.

    Returns:
        Status message about the AJAX spider task.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url)
    try:
        resp = _api("GET", "/JSON/ajaxSpider/action/scan/", params={
            "url": target_url,
        })
        if resp.status_code == 200:
            return f"AJAX Spider started on {target_url}. Use zap_ajax_spider_status() to check progress."
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_ajax_spider_status() -> str:
    """
    Check the status of the running AJAX spider.

    Returns:
        Current AJAX spider status (running/stopped).
    """
    err = _check_connection()
    if err:
        return err

    try:
        resp = _api("GET", "/JSON/ajaxSpider/view/status/")
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("status", "unknown")
            return f"AJAX Spider status: {status}"
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_add_to_context(
    target_url: str | int,
    context_name: str | int = "Default Context",
) -> str:
    """
    Add a URL to ZAP's scan context (equivalent to Burp's scope).

    Args:
        target_url: URL regex pattern to include (e.g. http://target.com.*).
        context_name: Context name (default: 'Default Context').

    Returns:
        Confirmation message.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url)
    context_name = str(context_name)

    try:
        # Ensure pattern covers the full site
        if not target_url.endswith(".*"):
            pattern = target_url.rstrip("/") + ".*"
        else:
            pattern = target_url

        resp = _api("GET", "/JSON/context/action/includeInContext/", params={
            "contextName": context_name,
            "regex": pattern,
        })
        if resp.status_code == 200:
            return f"Added {pattern} to context '{context_name}'."
        return f"Error: HTTP {resp.status_code} - {resp.text}"
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


@mcp.tool()
def zap_generate_report(
    target_url: Optional[str | int] = None,
    report_type: str | int = "traditional-html",
) -> str:
    """
    Generate a scan report from ZAP findings.

    Args:
        target_url: Optional target URL to filter the report.
        report_type: Report format - 'traditional-html' (default), 'traditional-xml', 'traditional-json'.

    Returns:
        Path to the generated report or report content summary.
    """
    err = _check_connection()
    if err:
        return err

    target_url = str(target_url) if target_url is not None else None
    report_type = str(report_type)

    try:
        # Get alerts summary for a quick text report
        params = {"start": "0", "count": "500"}
        if target_url:
            params["baseurl"] = target_url

        resp = _api("GET", "/JSON/alert/view/alerts/", params=params)
        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code}"

        alerts = resp.json().get("alerts", [])

        # Group by risk
        by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for a in alerts:
            risk = a.get("risk", "Informational")
            if risk in by_risk:
                by_risk[risk].append(a)

        lines = ["=== ZAP Scan Report ===\n"]
        for risk in ["High", "Medium", "Low", "Informational"]:
            items = by_risk[risk]
            if items:
                lines.append(f"\n[{risk.upper()}] ({len(items)} findings)")
                seen = set()
                for a in items:
                    name = a.get("name", a.get("alert", "Unknown"))
                    if name not in seen:
                        seen.add(name)
                        count = sum(1 for x in items if x.get("name", x.get("alert")) == name)
                        lines.append(f"  - {name} ({count} instance{'s' if count > 1 else ''})")

        total = len(alerts)
        lines.append(f"\nTotal: {total} alert(s)")
        return "\n".join(lines)
    except requests.ConnectionError:
        return f"Cannot connect to ZAP at {ZAP_API_URL}."


if __name__ == "__main__":
    mcp.run(transport="sse")
