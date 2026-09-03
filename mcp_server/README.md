# 5G-Core-Analyzer MCP Server

AI-powered troubleshooting agent for Open5GS + UERANSIM 5G core networks.

## Prerequisites

```bash
pip install mcp
```

## Registration

Add to `kilo.json`:
```json
{
  "mcpServers": {
    "5g-troubleshooter": {
      "command": "/opt/homebrew/bin/python3.14",
      "args": ["mcp_server/server.py"],
      "cwd": "/path/to/5g-core-analyzer"
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `analyze_5g_logs` | Scan Open5GS logs for errors and pattern matches |
| `get_container_status` | Check all 5G container statuses |
| `diagnose_issue` | Diagnose known 5G error patterns (FIVEG_SERVICES_NOT_ALLOWED, SQN out of range, No UPF, etc.) |
| `suggest_resolution` | Get step-by-step fix plan for diagnosed issues |
| `log_resolution` | Log an AI resolution action for auditing |
| `get_resolution_history` | Retrieve all past resolution actions |

## Resolution Tracking

All resolutions are logged to `mcp_server/resolution_log.jsonl` with timestamp, action, issue, resolution, and result fields.
