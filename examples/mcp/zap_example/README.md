# OWASP ZAP MCP Server for CAI

MCP server that exposes OWASP ZAP's REST API as tools usable by CAI agents.

## Prerequisites

1. **OWASP ZAP** installed:
   ```bash
   sudo snap install zaproxy --classic
   # or
   sudo apt install zaproxy
   ```

2. **Python dependencies**:
   ```bash
   pip install "mcp[server]" requests
   ```

## Quick Start

```bash
# 1. Start ZAP in daemon mode (headless, no API key)
zaproxy -daemon -port 8080 -config api.disablekey=true

# 2. Start the MCP server
python server.py

# 3. In CAI, connect and use:
/mcp load http://localhost:8000/sse zap
/mcp add zap <agent_name>
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `ZAP_API_URL` | `http://localhost:8080` | ZAP API URL |
| `ZAP_API_KEY` | (empty) | API key (if not disabled) |

## Available Tools

| Tool | Description |
|---|---|
| `zap_scan` | Launch active scan on a target |
| `zap_scan_status` | Check active scan progress |
| `zap_spider` | Crawl a target to discover content |
| `zap_spider_status` | Check spider progress |
| `zap_ajax_spider` | AJAX spider for JS-heavy apps |
| `zap_ajax_spider_status` | Check AJAX spider status |
| `zap_get_alerts` | List vulnerabilities found |
| `zap_get_alert_details` | Get full details of a specific alert |
| `zap_sitemap` | Retrieve discovered URLs |
| `zap_add_to_context` | Add URL to scan context (scope) |
| `zap_generate_report` | Generate scan report summary |

## Usage Example in CAI

```
/mcp load http://localhost:8000/sse zap
/mcp add zap "Recon Agent"

> Spider and scan http://target.com for vulnerabilities using ZAP,
  then analyze the findings and suggest exploitation paths.
```

The agent will use `zap_spider`, `zap_scan`, `zap_scan_status`,
and `zap_get_alerts` autonomously to complete the task.

## Burp Suite vs ZAP Tool Mapping

| Burp Suite tool | ZAP equivalent |
|---|---|
| `burp_scan` | `zap_scan` |
| `burp_scan_status` | `zap_scan_status` |
| `burp_spider` | `zap_spider` |
| `burp_sitemap` | `zap_sitemap` |
| `burp_get_issues` | `zap_get_alerts` |
| `burp_get_issue_details` | `zap_get_alert_details` |
| `burp_add_to_scope` | `zap_add_to_context` |
| `burp_scope_check` | (use `zap_add_to_context`) |
| `burp_proxy_history` | (not needed, use alerts) |
| `burp_send_to_repeater` | (not needed, use `generic_linux_command` with curl) |
