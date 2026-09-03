#!/usr/bin/env python3
"""
Test the reactive MCP server against simulated 5G network failures.

Usage:
  python3 test_reactive_mcp.py
"""

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

MCP_SERVER = "/Users/guillermopineda/5g-core-analyzer/mcp_server/reactive_server.py"
PYTHON_BIN = "/opt/homebrew/bin/python3.14"
LOG_DIR = "/Users/guillermopineda/docker-open5gs/logs"

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

passed = 0
failed = 0


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  {GREEN}[PASS]{NC} {name}")
        passed += 1
    else:
        print(f"  {RED}[FAIL]{NC} {name} {detail}")
        failed += 1


async def run_client():
    global passed, failed

    from mcp import stdio_client
    from mcp.client.stdio import StdioServerParameters
    from mcp.client.session import ClientSession

    server_params = StdioServerParameters(
        command=PYTHON_BIN,
        args=[MCP_SERVER],
        cwd="/Users/guillermopineda/5g-core-analyzer",
    )

    print(f"{YELLOW}=== Reactive MCP Server Test ===\n{NC}")

    async with stdio_client(server=server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print(f"{YELLOW}1. Server connected - testing tool availability...{NC}")

            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            expected = ["get_container_status", "diagnose_issue", "suggest_resolution",
                       "log_resolution", "get_resolution_history", "get_reactive_alerts",
                       "force_check_logs"]
            for t in expected:
                test(f"Tool '{t}' available", t in tool_names)

            # ── Force check logs ──────────────────────────────────────
            print(f"\n{YELLOW}2. Forcing log analysis...{NC}")
            result = await session.call_tool("force_check_logs", {})
            data = json.loads(result.content[0].text)
            if isinstance(data, list):
                test("Force check returns issues", True, f"found {len(data)} issue types")
                for d in data[:3]:
                    print(f"    - {d.get('pattern','?')}: {d.get('details','')[:60]}")
            else:
                test("Force check returns issues", False, str(data)[:100])

            # ── Inject failure scenario ─────────────────────────────────
            print(f"\n{YELLOW}3. Injecting 6 SMF timeout ERROR lines...{NC}")
            ts = datetime.now().strftime("%H:%M:%S")
            log_file = Path(LOG_DIR) / "smf.log"
            with open(log_file, "a") as f:
                for i in range(6):
                    f.write(f"09/03 {ts}.{i*100:03d}: [smf] ERROR: No suitable UPF found for session reactive_test_{i} (../src/smf/context.c:1210)\n")
            print(f"    Injected 6 lines into {log_file.name}")

            # ── Wait for reactive detection ──────────────────────────────
            print(f"{YELLOW}4. Waiting 5s for reactive detection...{NC}")
            await asyncio.sleep(5)

            result = await session.call_tool("get_reactive_alerts", {})
            alerts = json.loads(result.content[0].text)
            test("Reactive alerts detected", isinstance(alerts, list) and len(alerts) > 0,
                 f"got {len(alerts) if isinstance(alerts, list) else type(alerts)}")

            if isinstance(alerts, list) and len(alerts) > 0:
                for a in alerts[-5:]:
                    print(f"    [{a.get('timestamp','?')[:19]}] {a.get('pattern','?')}: {a.get('status','?')}")

            # ── Check resolution history ────────────────────────────────
            print(f"\n{YELLOW}5. Checking resolution history...{NC}")
            result = await session.call_tool("get_resolution_history", {"limit": 10})
            history = json.loads(result.content[0].text)
            test("Resolution history accessible", isinstance(history, list) and len(history) > 0,
                 f"got {len(history) if isinstance(history, list) else 0}")
            if isinstance(history, list) and len(history) > 0:
                print(f"    {len(history)} resolution entries found")
                for h in history[-3:]:
                    print(f"    [{h.get('timestamp','?')[:19]}] {h.get('action','?')}")

            # ── Diagnose the injected issue ─────────────────────────────
            print(f"\n{YELLOW}6. Diagnosing injected issue...{NC}")
            result = await session.call_tool("diagnose_issue", {
                "error_text": "No suitable UPF found for session"
            })
            data = json.loads(result.content[0].text)
            if data.get("matches"):
                test("Diagnosis returned", True)
                for m in data["matches"]:
                    print(f"    Pattern: {m['pattern']}")
                    print(f"    Fix: {m['resolution'][:60]}...")
            else:
                test("Diagnosis returned", False)

            # ── Get resolution suggestion ───────────────────────────────
            print(f"\n{YELLOW}7. Getting resolution suggestion...{NC}")
            result = await session.call_tool("suggest_resolution", {
                "issue": "No suitable UPF found for session",
                "diagnosis": "UPF not registered via PFCP"
            })
            data = json.loads(result.content[0].text)
            test("Resolution steps returned", len(data.get("steps", [])) > 0)
            for s in data.get("steps", []):
                print(f"    {s}")


    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    total = passed + failed
    print(f"  Results: {GREEN}{passed} passed{NC}, {RED}{failed} failed{NC} (of {total})")
    print(f"{'='*50}")

    # Cleanup
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        filtered = [l for l in lines if "reactive_test" not in l]
        with open(log_file, "w") as f:
            f.writelines(filtered)
    except:
        pass

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(run_client())
