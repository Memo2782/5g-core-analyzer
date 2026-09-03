#!/usr/bin/env python3
"""
Scenario generator for testing the reactive MCP server.

Simulates realistic 5G network failures by injecting error log lines
into Open5GS log files, allowing the reactive MCP server to detect
and respond to issues autonomously.

Scenarios:
  1. SMF timeout burst (5x SMF ERROR lines)
  2. UE registration failure (FIVEG_SERVICES_NOT_ALLOWED)
  3. SQN synchronization failure (auth ERROR)
  4. PCF session anomaly (PCF ERROR lines)
  5. AUSF authentication failure burst

Usage:
  python3 generate_scenario.py [scenario_number]
  python3 generate_scenario.py all
"""

import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("/Users/guillermopineda/docker-open5gs/logs")
IMSIS = ["001011234567891", "001010000000001", "001010000000002"]


def inject_log(filename: str, lines: list[str], delay: float = 0.5):
    """Inject log lines into a file with optional delay between lines."""
    filepath = LOG_DIR / filename
    print(f"  → Injecting into {filename}...")
    for line in lines:
        ts = f"09/03 {datetime.now().strftime('%H:%M:%S')}.{random.randint(100, 999)}"
        with open(filepath, "a") as f:
            f.write(f"{ts}: {line}\n")
        print(f"    {line[:80]}")
        time.sleep(delay)


def scenario_1_smf_timeout():
    """Scenario 1: SMF timeout burst from 5 x 503 errors."""
    print("\n[Scenario 1: SMF Timeout Burst]")
    lines = [
        "[smf] ERROR: No suitable UPF found for session (../src/smf/context.c:1210)",
        "[smf] ERROR: [imsi-001011234567891:1] No UPF available for session (../src/smf/npcf-handler.c:480)",
        "[smf] ERROR: smf_npcf_smpolicycontrol_handle_create() failed (../src/smf/gsm-sm.c:630)",
        "[smf] ERROR: No suitable UPF found for session (../src/smf/context.c:1210)",
        "[smf] ERROR: [imsi-001011234567891:2] No UPF available for session (../src/smf/npcf-handler.c:480)",
    ]
    inject_log("smf.log", lines)
    print("  → SMF timeout burst injected (5 errors)")


def scenario_2_registration_failure():
    """Scenario 2: UE registration failure - FIVEG_SERVICES_NOT_ALLOWED."""
    print("\n[Scenario 2: UE Registration Failure]")
    imsi = random.choice(IMSIS)
    lines = [
        f"[amf] ERROR: [suci-0-001-01-0000-0-0-{imsi[-10:}] SUCI lookup failed (../src/amf/gmm-sm.c:1800)",
        f"[udm] ERROR: [imsi-{imsi}] HTTP response error [404] (../src/udm/gmm-sm.c:2591)",
        f"[amf] ERROR: [suci-0-001-01-0000-0-0-{imsi[-10:}] Registration reject [7] (../src/amf/nas-path.c:213)",
        "[amf] ERROR: FIVEG_SERVICES_NOT_ALLOWED (../src/amf/gmm.c:1595)",
        f"[amf] ERROR: [imsi-{imsi}] Cannot receive SBI message (../src/amf/nsmf-handler.c:947)",
    ]
    inject_log("amf.log", lines)
    print(f"  → UE registration failure injected (IMSI: {imsi})")


def scenario_3_sqn_failure():
    """Scenario 3: SQN synchronization failure."""
    print("\n[Scenario 3: SQN Synchronization Failure]")
    imsi = random.choice(IMSIS)
    lines = [
        f"[ausf] ERROR: [imsi-{imsi}] Authentication failure [21] (../src/ausf/uds-dr-path.c:444)",
        f"[ausf] ERROR: [imsi-{imsi}] SQN out of range, synch failure (../src/ausf/auth-event.c:312)",
        f"[udr] ERROR: [imsi-{imsi}] No 'security' field in this document (../lib/dbi/subscription.c:77)",
        f"[udr] WARNING: [imsi-{imsi}] Cannot find SUPI in DB (../src/udr/nudr-handler.c:68)",
        f"[amf] ERROR: [imsi-{imsi}] Authentication request failed, synch failure (../src/amf/gmm-sm.c:1825)",
    ]
    inject_log("amf.log", lines)
    inject_log("smf.log", lines[:2])
    print(f"  → SQN sync failure injected (IMSI: {imsi})")


def scenario_4_pcf_anomaly():
    """Scenario 4: PCF session anomaly."""
    print("\n[Scenario 4: PCF Session Anomaly]")
    lines = [
        "[pcf] ERROR: No suitable PCF found for DNN[internet] (../src/pcf/path.c:736)",
        "[pcf] ERROR: SMF Profile not found in NRF (../src/pcf/nnrf.c:777)",
        "[smf] ERROR: [imsi-001011234567891:1] SMF create sm-context failed [500] (../src/smf/nsmf-handler.c:1178)",
        "[smf] ERROR: [imsi-001011234567891:1] SMF update sm-context failed [500] (../src/smf/nsmf-handler.c:1317)",
        "[sbi] ERROR: HTTP response error [502] from PCF (../lib/sbi/path.c:307)",
    ]
    inject_log("smf.log", lines)
    print("  → PCF session anomaly injected")


def scenario_5_ausf_failure_burst():
    """Scenario 5: AUSF authentication failure burst."""
    print("\n[Scenario 5: AUSF Auth Failure Burst]")
    imsis = random.sample(IMSIS, min(4, len(IMSIS)))
    lines = []
    for imsi in imsis:
        lines.extend([
            f"[ausf] ERROR: [imsi-{imsi}] HTTP response error [401] (../src/ausf/uds-dr-path.c:444)",
            f"[ausf] ERROR: [imsi-{imsi}] Authentication request failed [MAC verification failed] (../src/ausf/auth-event.c:312)",
        ])
    inject_log("amf.log", lines)
    print(f"  → AUSF auth failure burst injected ({len(imsis)} subscribers)")


SCENARIOS = {
    "1": scenario_1_smf_timeout,
    "2": scenario_2_registration_failure,
    "3": scenario_3_sqn_failure,
    "4": scenario_4_pcf_anomaly,
    "5": scenario_5_ausf_failure_burst,
}


def run_scenario(num: str):
    if num == "all":
        for n in SCENARIOS:
            SCENARIOS[n]()
            time.sleep(2)
    elif num in SCENARIOS:
        SCENARIOS[num]()
    else:
        print(f"Unknown scenario: {num}")
        print(f"Available: {', '.join(SCENARIOS.keys())}, or 'all'")
        sys.exit(1)


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "all"
    print(f"{'='*50}")
    print(f"  5G Network Failure Scenario Generator")
    print(f"{'='*50}")
    run_scenario(scenario)
    print(f"\n{'='*50}")
    print("  Scenario injection complete.")
    print("  Check reactive MCP server for auto-detection.")
    print(f"{'='*50}")
