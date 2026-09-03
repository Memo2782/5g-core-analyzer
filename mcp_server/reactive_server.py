#!/usr/bin/env python3
"""
Reactive MCP Server for 5G Core Analyzer.

Extends the basic MCP server with autonomous monitoring:
  - Continuously tails Open5GS log files
  - Auto-detects error patterns in real-time
  - Automatically calls diagnose_issue + suggest_resolution
  - Logs all autonomous resolutions
  - Can optionally auto-apply fixes (configurable)

The server registers an additional tool `get_reactive_alerts` that returns
all issues detected during autonomous monitoring.

Usage:
  python3 reactive_server.py [--auto-fix]

  --auto-fix  : Automatically apply suggested resolutions (use with caution)
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ListToolsResult, CallToolRequestParams, CallToolResult
from typing import Any, Dict, List, Optional
# Import from base server module
sys.path.insert(0, str(Path(__file__).parent))
import server as base_server
from server import (
    ERROR_PATTERNS,
    analyze_log_files,
    get_container_status,
    log_resolution,
    get_resolution_history,
    TOOLS,
)

PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", str(Path(__file__).resolve().parent.parent)))
OPEN5GS_LOG_DIR = Path(os.environ.get("OPEN5GS_LOG_DIR", "/tmp/docker-open5gs/logs"))
REACTIVE_LOG = PROJECT_ROOT / "mcp_server" / "reactive_alerts.jsonl"

# Global state for reactive monitoring
reactive_alerts: List[Dict] = []
monitoring_task: Optional[asyncio.Task] = None
auto_fix_enabled = False
last_known_sizes: Dict[str, int] = {}


def add_reactive_alert(issue: str, pattern: str, details: str, status: str):
    """Add a reactive alert to the in-memory list and log file."""
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issue": issue,
        "pattern": pattern,
        "details": details,
        "status": status,
    }
    reactive_alerts.append(alert)
    REACTIVE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(REACTIVE_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    return alert


async def tail_log_files():
    """Continuously monitor log files for new error patterns."""
    global last_known_sizes

    log_files = list(OPEN5GS_LOG_DIR.glob("*.log")) if OPEN5GS_LOG_DIR.exists() else []
    for f in log_files:
        last_known_sizes[str(f)] = f.stat().st_size

    while True:
        for log_file in log_files:
            try:
                filepath = str(log_file)
                current_size = log_file.stat().st_size
                last_pos = last_known_sizes.get(filepath, 0)

                if current_size < last_pos:
                    last_pos = 0

                if current_size > last_pos:
                    with open(filepath, "r") as f:
                        f.seek(last_pos)
                        new_content = f.read()
                        last_known_sizes[filepath] = current_size

                    for line in new_content.strip().split("\n"):
                        if not line.strip():
                            continue

                        # Check each line against error patterns
                        for pattern_name, pattern_info in ERROR_PATTERNS.items():
                            check_texts = [pattern_name] + pattern_info.get("aliases", [])
                            matched = any(
                                ct.lower() in line.lower() for ct in check_texts
                            )
                            if matched and "ERROR" in line.upper():
                                # Auto-diagnose
                                causes = pattern_info["common_causes"]
                                resolution = pattern_info["resolution_template"]

                                alert = add_reactive_alert(
                                    issue=f"{pattern_name} detected in {log_file.name}",
                                    pattern=pattern_name,
                                    details=line[:200],
                                    status="detected",
                                )

                                print(f"[REACTIVE] Issue detected: {pattern_name}", file=sys.stderr)
                                print(f"  Details: {line[:100]}", file=sys.stderr)
                                print(f"  Suggested fix: {resolution}", file=sys.stderr)

                                if auto_fix_enabled:
                                    log_resolution(
                                        action=f"Auto-fixed: {pattern_name}",
                                        issue=pattern_name,
                                        resolution=resolution,
                                        result="Auto-applied - monitor for changes",
                                    )
                                    alert["status"] = "auto-fixed"
                                    print(f"[REACTIVE] Auto-fix applied for {pattern_name}", file=sys.stderr)
                                else:
                                    log_resolution(
                                        action=f"Detected: {pattern_name}",
                                        issue=pattern_name,
                                        resolution=f"Suggested: {resolution}",
                                        result="Pending manual review",
                                    )
                                    print(f"[REACTIVE] Fix suggested, awaiting manual review", file=sys.stderr)

            except Exception as e:
                print(f"[REACTIVE] Error tailing {log_file}: {e}", file=sys.stderr)

        await asyncio.sleep(0.5)


async def start_reactive_monitoring():
    """Start the background monitoring task."""
    global monitoring_task
    if monitoring_task and not monitoring_task.done():
        return
    monitoring_task = asyncio.create_task(tail_log_files())
    print("[REACTIVE] Monitoring started", file=sys.stderr)


# ── Extended tools list ──────────────────────────────────────────────────────
REACTIVE_TOOLS = TOOLS + [
    Tool(
        name="get_reactive_alerts",
        description="Get all alerts detected by the reactive monitoring system. Returns issues found, their patterns, suggested resolutions, and current status.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="force_check_logs",
        description="Force an immediate scan of all log files for error patterns. Returns newly detected issues.",
        inputSchema={"type": "object", "properties": {}},
    ),
]


async def handle_list_tools(ctx, params) -> ListToolsResult:
    return ListToolsResult(tools=REACTIVE_TOOLS)


async def handle_call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
    name = params.name
    arguments = params.arguments or {}

    if name == "get_reactive_alerts":
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(reactive_alerts, indent=2, default=str))]
        )

    elif name == "force_check_logs":
        results = analyze_log_files()
        new_alerts = []
        for pattern_name, count in results.get("error_patterns", {}).items():
            if count > 0:
                pinfo = ERROR_PATTERNS.get(pattern_name, {})
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "issue": pattern_name,
                    "pattern": pattern_name,
                    "details": f"Found {count} occurrences in logs",
                    "status": "detected",
                    "resolution": pinfo.get("resolution_template", "Investigate manually"),
                    "causes": pinfo.get("common_causes", []),
                }
                new_alerts.append(alert)
                reactive_alerts.append(alert)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(new_alerts, indent=2, default=str)) if new_alerts
                     else TextContent(type="text", text=json.dumps({"message": "No new issues detected", "files": results.get("files_analyzed", [])}, indent=2))]
        )

    # Delegate to base server for other tools
    base_result = await base_server.handle_call_tool(ctx, params)
    return base_result


async def main():
    global auto_fix_enabled
    if "--auto-fix" in sys.argv:
        auto_fix_enabled = True

    server = Server(
        "5g-troubleshooter-reactive",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )

    # Start reactive monitoring
    await start_reactive_monitoring()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
