#!/usr/bin/env python3
"""
Test the 5G-Core-Analyzer MCP Server.

This script exercises all 6 MCP tools:
  1. get_container_status     - verify all 5G containers
  2. analyze_5g_logs          - scan Open5GS log files for errors
  3. diagnose_issue           - map an error pattern to root causes
  4. suggest_resolution       - get a step-by-step fix plan
  5. log_resolution           - record a resolution action
  6. get_resolution_history   - retrieve all logged resolutions

Usage:
  python3 test_mcp_server.py
  or
  /opt/homebrew/bin/python3.14 test_mcp_server.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

try:
    from mcp import stdio_client
    from mcp.client.stdio import StdioServerParameters
    from mcp.client.session import ClientSession
except ImportError:
    print("[!] MCP package not installed. Install with:")
    print("    /opt/homebrew/bin/python3.14 -m pip install --break-system-packages mcp")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
MCP_SERVER = SCRIPT_DIR / "server.py"
OPEN5GS_LOG_DIR = os.environ.get("OPEN5GS_LOG_DIR", str(PROJECT_ROOT / ".." / "docker-open5gs" / "logs"))

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

passed = 0
failed = 0


def ok(msg: str):
    global passed
    passed += 1
    print(f"  {GREEN}[PASS]{NC} {msg}")


def bad(msg: str):
    global failed
    failed += 1
    print(f"  {RED}[FAIL]{NC} {msg}")


async def run_tool(session, name: str, args: dict = None):
    """Call an MCP tool and return parsed JSON result."""
    result = await session.call_tool(name, arguments=args or {})
    text = result.content[0].text
    return json.loads(text)


async def main():
    if not MCP_SERVER.exists():
        print(f"[!] MCP server not found at {MCP_SERVER}")
        sys.exit(1)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(MCP_SERVER)],
        cwd=str(PROJECT_ROOT),
        env={
            "OPEN5GS_LOG_DIR": OPEN5GS_LOG_DIR,
            "PROJECT_ROOT": str(PROJECT_ROOT),
        },
    )

    print(f"{YELLOW}Starting MCP server...{NC}")
    async with stdio_client(server=server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init = await session.initialize()
            print(f"  Server: {init.server_info.name}\n")

            # ── Test 1: Container Status ──────────────────────────────────────
            print(f"{YELLOW}Test 1: get_container_status{NC}")
            try:
                data = await run_tool(session, "get_container_status")
                for c, s in data.items():
                    print(f"  {c}: {s}")
                if len(data) >= 11:
                    ok(f"All containers checked ({len(data)} found)")
                else:
                    bad(f"Expected 11 containers, got {len(data)}")
            except Exception as e:
                bad(f"get_container_status failed: {e}")

            # ── Test 2: Analyze Logs ──────────────────────────────────────────
            print(f"\n{YELLOW}Test 2: analyze_5g_logs{NC}")
            try:
                data = await run_tool(session, "analyze_5g_logs")
                print(f"  Files: {data.get('files_analyzed', [])}")
                print(f"  Errors: {len(data.get('errors', []))}")
                print(f"  Warnings: {len(data.get('warnings', []))}")
                print(f"  Patterns: {data.get('error_patterns', {})}")
                if "files_analyzed" in data:
                    ok("Log analysis completed")
                else:
                    bad("analyze_5g_logs returned unexpected format")
            except Exception as e:
                bad(f"analyze_5g_logs failed: {e}")

            # ── Test 3: Diagnose Issue ────────────────────────────────────────
            print(f"\n{YELLOW}Test 3: diagnose_issue{NC}")
            test_errors = [
                "FIVEG_SERVICES_NOT_ALLOWED",
                "No suitable UPF found for session",
                "No 'security' field in this document",
                "SQN out of range",
            ]
            for err_text in test_errors:
                try:
                    data = await run_tool(session, "diagnose_issue", {"error_text": err_text})
                    if data["matches"]:
                        m = data["matches"][0]
                        print(f"  '{err_text}' → {m['pattern']}: {m['description'][:50]}...")
                        ok(f"Diagnosed: {m['pattern']}")
                    else:
                        bad(f"No pattern matched for: {err_text}")
                except Exception as e:
                    bad(f"diagnose_issue failed for '{err_text}': {e}")

            # ── Test 4: Suggest Resolution ────────────────────────────────────
            print(f"\n{YELLOW}Test 4: suggest_resolution{NC}")
            try:
                data = await run_tool(session, "suggest_resolution", {
                    "issue": "No suitable UPF found for session",
                    "diagnosis": "UPF not registered",
                })
                for step in data.get("steps", []):
                    print(f"  {step}")
                print(f"  Recommended: {data.get('recommended_action', 'N/A')[:80]}...")
                if data.get("steps"):
                    ok(f"Got {len(data['steps'])} resolution steps")
                else:
                    bad("No resolution steps returned")
            except Exception as e:
                bad(f"suggest_resolution failed: {e}")

            # ── Test 5: Log Resolution ────────────────────────────────────────
            print(f"\n{YELLOW}Test 5: log_resolution{NC}")
            try:
                data = await run_tool(session, "log_resolution", {
                    "action": "Test resolution via MCP",
                    "issue": "Test issue for MCP validation",
                    "resolution": "Validated MCP server tools are working",
                    "result": "Success - all tests passed",
                })
                print(f"  Timestamp: {data.get('timestamp', 'N/A')}")
                print(f"  Action: {data.get('action', 'N/A')}")
                ok("Resolution logged successfully")
            except Exception as e:
                bad(f"log_resolution failed: {e}")

            # ── Test 6: Get Resolution History ────────────────────────────────
            print(f"\n{YELLOW}Test 6: get_resolution_history{NC}")
            try:
                data = await run_tool(session, "get_resolution_history", {"limit": 10})
                print(f"  Found {len(data)} resolution entries")
                for entry in data[-3:]:
                    print(f"  [{entry.get('timestamp', '?')[:19]}] {entry.get('action', '?')}")
                ok(f"Retrieved {len(data)} resolution history entries")
            except Exception as e:
                bad(f"get_resolution_history failed: {e}")

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    total = passed + failed
    print(f"  Results: {GREEN}{passed} passed{NC}, {RED}{failed} failed{NC} (of {total})")
    print(f"{'='*50}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
