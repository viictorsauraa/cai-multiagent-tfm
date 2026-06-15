# Burp Suite MCP Server for CAI

MCP server that exposes Burp Suite's REST API as tools usable by CAI agents.

## Prerequisites

1. **Burp Suite Professional** running with REST API enabled:
   - Option A: [burp-rest-api extension](https://github.com/vmware/burp-rest-api) (default port 1337)
   - Option B: Burp Suite v2024+ built-in REST API

2. **Python dependencies**:
   ```bash
   pip install "mcp[server]" requests
   ```

## Quick Start

```bash
# 1. Start the MCP server
python server.py

# 2. In CAI, connect and use:
/mcp load http://localhost:8000/sse burp
/mcp add burp <agent_name>
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `BURP_API_URL` | `http://localhost:1337` | Burp Suite REST API URL |
| `BURP_API_KEY` | (empty) | API key for authentication |

## Available Tools

| Tool | Description |
|---|---|
| `burp_scan` | Launch active/passive scan on a target |
| `burp_scan_status` | Check scan progress |
| `burp_spider` | Crawl a target to discover content |
| `burp_sitemap` | Retrieve discovered URLs |
| `burp_get_issues` | List vulnerabilities found |
| `burp_get_issue_details` | Get full details of a specific issue |
| `burp_proxy_history` | View recent proxied requests |
| `burp_send_to_repeater` | Send a crafted request to Repeater |
| `burp_scope_check` | Check if URL is in target scope |
| `burp_add_to_scope` | Add URL to target scope |

## Usage Example in CAI

```
/mcp load http://localhost:8000/sse burp
/mcp add burp redteam_agent
/agent redteam_agent

> Scan http://target.com for vulnerabilities using Burp Suite,
  then analyze the findings and suggest exploitation paths.
```

The agent will use `burp_add_to_scope`, `burp_scan`, `burp_scan_status`,
and `burp_get_issues` autonomously to complete the task.
