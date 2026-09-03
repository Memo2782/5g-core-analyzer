#!/usr/bin/env python3
"""
MCP Server for 5G Core Analyzer - AI Troubleshooting Agent

Provides tools for AI to analyze 5G logs, diagnose issues, suggest resolutions,
and track all resolution actions performed.

Usage:
  python3 server.py

Register in kilo.json:
  {
    "mcpServers": {
      "5g-troubleshooter": {
        "command": "/opt/homebrew/bin/python3.14",
        "args": [".../mcp_server/server.py"],
        "cwd": ".../5g-core-analyzer"
      }
    }
  }
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ListToolsResult, CallToolRequestParams, CallToolResult

# Configuration
PROJECT_ROOT = Path("/Users/guillermopineda/5g-core-analyzer")
OPEN5GS_LOG_DIR = Path("/Users/guillermopineda/docker-open5gs/logs")
RESOLUTION_LOG = PROJECT_ROOT / "mcp_server" / "resolution_log.jsonl"

# Common 5G error patterns and resolutions
ERROR_PATTERNS = {
    "FIVEG_SERVICES_NOT_ALLOWED": {
        "description": "UE registration rejected - 5G services not allowed by AMF",
        "common_causes": [
            "Subscriber not found in UDR (missing security field in DB)",
            "Subscriber profile missing required fields (slice, ambr, etc.)",
            "UDM cannot discover UDR via NRF",
        ],
        "resolution_template": "Check MongoDB subscriber data schema, ensure security field uses flat opc string, verify UDR-NRF registration",
    },
    "sqn_out_of_range": {
        "description": "SQN (sequence number) synchronization failure between UE and UDM/UDR",
        "common_causes": [
            "SQN mismatch due to all-zero keys",
            "SQN field format incorrect in DB (should be NumberLong)",
            "Duplicate subscriber documents causing SQN confusion",
        ],
        "resolution_template": "Reset SQN to NumberLong(0), remove duplicate subscribers, restart UE",
        "aliases": ["sqn out of range", "sqn sync", "sequence number"],
    },
    "No suitable UPF": {
        "description": "SMF cannot find a UPF for session establishment",
        "common_causes": [
            "UPF container not running",
            "UPF missing /dev/net/tun device",
            "UPF not registered via PFCP",
            "UPF pfcp.client.smf not configured",
        ],
        "resolution_template": "Add /dev/net/tun device mapping, configure pfcp.client.smf in UPF config, restart UPF",
    },
    "No 'security' field": {
        "description": "UDR cannot find security credentials in subscriber document",
        "common_causes": [
            "Using legacy 'auth' field instead of 'security'",
            "opc stored as nested object instead of string",
            "sqn stored as object instead of NumberLong",
        ],
        "resolution_template": "Migrate auth to security field, flatten opc to string, convert sqn to NumberLong",
    },
    "No UE-AMBR": {
        "description": "UDR cannot find UE-Aggregate Maximum Bit Rate in subscriber document",
        "common_causes": [
            "Missing ambr field in subscriber document",
            "Missing slice/session structure",
        ],
        "resolution_template": "Add ambr and slice array with session data to subscriber document",
    },
    "No AccessAndMobilitySubscriptionData": {
        "description": "UDM cannot retrieve AM subscription data from UDR",
        "common_causes": [
            "Missing slice array in subscriber document",
            "Missing default_indicator flag",
        ],
        "resolution_template": "Add slice array with default_indicator=true and session entries",
    },
    "Registration reject": {
        "description": "AMF rejected UE registration",
        "common_causes": [
            "Subscriber not provisioned in MongoDB",
            "Security field format mismatch (auth vs security)",
            "SQN synchronization failure",
        ],
        "resolution_template": "Check subscriber MongoDB document, fix security field format, reset SQN",
    },
}

TOOLS = [
    Tool(
        name="analyze_5g_logs",
        description="Analyze Open5GS log files for errors and common 5G issues. Returns error counts, warnings, and detected error patterns.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="get_container_status",
        description="Check the status of all 5G core containers (AMF, SMF, UPF, UDM, UDR, AUSF, PCF, NRF, DB, UE, GNB).",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="diagnose_issue",
        description="Diagnose a specific 5G issue based on its error message or pattern. Returns common causes and recommended resolution steps.",
        inputSchema={
            "type": "object",
            "properties": {
                "error_text": {
                    "type": "string",
                    "description": "The error message or pattern to diagnose",
                },
            },
            "required": ["error_text"],
        },
    ),
    Tool(
        name="suggest_resolution",
        description="Get a step-by-step resolution plan for a detected 5G issue. Logs the suggestion for tracking.",
        inputSchema={
            "type": "object",
            "properties": {
                "issue": {"type": "string", "description": "The issue to resolve"},
                "diagnosis": {"type": "string", "description": "The diagnosis from diagnose_issue"},
            },
            "required": ["issue"],
        },
    ),
    Tool(
        name="log_resolution",
        description="Log a resolution action performed by the AI agent. Creates an auditable record of the fix applied.",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "What action was taken"},
                "issue": {"type": "string", "description": "The issue that was fixed"},
                "resolution": {"type": "string", "description": "The specific fix applied"},
                "result": {"type": "string", "description": "Outcome of the fix"},
            },
            "required": ["action", "issue", "resolution", "result"],
        },
    ),
    Tool(
        name="get_resolution_history",
        description="Retrieve the history of all resolution actions performed by the AI agent. Useful for auditing and learning.",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max number of entries to return (default: 50)", "default": 50},
            },
        },
    ),
]


def log_resolution(action: str, issue: str, resolution: str, result: str) -> Dict:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "issue": issue,
        "resolution": resolution,
        "result": result,
    }
    RESOLUTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(RESOLUTION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def analyze_log_files() -> Dict[str, Any]:
    results = {"files_analyzed": [], "errors": [], "warnings": [], "error_patterns": {}}
    if not OPEN5GS_LOG_DIR.exists():
        results["error"] = f"Log directory not found: {OPEN5GS_LOG_DIR}"
        return results

    for log_file in sorted(OPEN5GS_LOG_DIR.glob("*.log")):
        try:
            content = log_file.read_text()
            lines = content.strip().split("\n")
            results["files_analyzed"].append(log_file.name)
            for line in lines:
                if "ERROR" in line:
                    results["errors"].append({"file": log_file.name, "line": line[:300]})
                    for pname, pinfo in ERROR_PATTERNS.items():
                        if pname.lower() in line.lower():
                            results["error_patterns"][pname] = results["error_patterns"].get(pname, 0) + 1
                elif "WARNING" in line:
                    results["warnings"].append({"file": log_file.name, "line": line[:300]})
        except Exception as e:
            results["errors"].append({"file": log_file.name, "line": f"Read error: {e}"})
    return results


def get_container_status() -> Dict[str, str]:
    import subprocess
    result = {}
    containers = ["amf", "smf", "upf", "udm", "udr", "ausf", "pcf", "nrf", "db", "ue", "gnb"]
    for container in containers:
        try:
            ps_result = subprocess.run(
                ["docker", "ps", "--format", "{{.Status}}", "--filter", f"name=^{container}$"],
                capture_output=True, text=True, timeout=5,
            )
            status = ps_result.stdout.strip()
            result[container] = status if status else "exited/stopped"
        except Exception as e:
            result[container] = f"error: {e}"
    return result


def get_resolution_history(limit: int = 50) -> List[Dict]:
    if not RESOLUTION_LOG.exists():
        return []
    entries = []
    with open(RESOLUTION_LOG, "r") as f:
        for line in f:
            entries.append(json.loads(line.strip()))
    return entries[-limit:]


async def handle_list_tools(ctx, params) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


async def handle_call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
    name = params.name
    arguments = params.arguments or {}
    
    if name == "analyze_5g_logs":
        results = analyze_log_files()
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(results, indent=2, default=str))])

    elif name == "get_container_status":
        results = get_container_status()
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(results, indent=2, default=str))])

    elif name == "diagnose_issue":
        error_text = arguments.get("error_text", "")
        diagnosis = {"error_text": error_text, "matches": []}
        for pname, pinfo in ERROR_PATTERNS.items():
            check_texts = [pname] + pinfo.get("aliases", [])
            for ct in check_texts:
                if ct.lower() in error_text.lower():
                    diagnosis["matches"].append({
                        "pattern": pname,
                        "description": pinfo["description"],
                        "common_causes": pinfo["common_causes"],
                        "resolution": pinfo["resolution_template"],
                    })
                    break
        diagnosis["result"] = (
            "Known issue patterns detected." if diagnosis["matches"]
            else "No known patterns matched. Manual investigation required."
        )
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(diagnosis, indent=2))])

    elif name == "suggest_resolution":
        issue = arguments.get("issue", "")
        diagnosis = arguments.get("diagnosis", "")
        resolution = {"issue": issue, "diagnosis": diagnosis, "steps": []}
        for pname, pinfo in ERROR_PATTERNS.items():
            check_texts = [pname] + pinfo.get("aliases", [])
            for ct in check_texts:
                if ct.lower() in issue.lower():
                    
                    resolution["steps"] = [f"Step {i+1}: {s}" for i, s in enumerate(pinfo["common_causes"])]
                    resolution["recommended_action"] = pinfo["resolution_template"]
                    break
            if resolution["steps"]:
                break
        if not resolution["steps"]:
            resolution["steps"] = ["Investigate container logs", "Check network connectivity", "Verify configuration"]
            resolution["recommended_action"] = "Manual investigation required"
        log_resolution("SUGGESTION", issue, resolution["recommended_action"], "Suggested")
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(resolution, indent=2))])

    elif name == "log_resolution":
        entry = log_resolution(
            arguments.get("action", "Unknown"),
            arguments.get("issue", "Unknown"),
            arguments.get("resolution", "Unknown"),
            arguments.get("result", "Unknown"),
        )
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(entry, indent=2))])

    elif name == "get_resolution_history":
        limit = arguments.get("limit", 50)
        history = get_resolution_history(limit)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(history, indent=2, default=str))])

    return CallToolResult(content=[TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))], is_error=True)


async def main():
    server = Server(
        "5g-troubleshooter",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
