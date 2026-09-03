#!/usr/bin/env python3
"""5G Core Alert Stream Test Suite"""
import json
import time
import subprocess
import sys

API_KEY = "5ga_F1i4N1Wdjnc7iR0rLQMozjXKrbVGgYlcD1r2TnfjZ5w"
BASE_URL = "http://localhost:8000"
TEST_FILE = "/Users/guillermopineda/5g-core-analyzer/data_samples/test_alarms.jsonl"

def generate_test_data():
    """Generate test log entries that trigger each alert rule."""
    base_time = time.time()
    entries = []
    
    for i in range(6):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": str(503 + (i % 2)),
            "source_nf": "SMF",
            "dest_nf": "UPF",
            "interface": "N11",
            "details": f"PFCP failure {i+1}"
        })
    
    for i in range(4):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": "401",
            "source_nf": "AUSF",
            "dest_nf": "UE",
            "interface": "N12",
            "details": f"Auth failure {i+1}"
        })
    
    for i in range(3):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": "503",
            "source_nf": "PCF",
            "dest_nf": "AMF",
            "interface": "N5",
            "details": f"Policy failure {i+1}"
        })
    
    for i in range(4):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": "404",
            "source_nf": "UDM",
            "dest_nf": "AMF",
            "interface": "N8",
            "details": f"Subscription missing {i+1}"
        })
    
    for i in range(6):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": "200",
            "source_nf": "PCSCF",
            "dest_nf": "UE",
            "interface": "Gm/Mw",
            "procedure": "SIP INVITE",
            "details": f"SIP response {i+1}"
        })
    
    for i in range(10):
        entries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(base_time + i)),
            "http_status": "4" + str(40 + (i % 10)),
            "source_nf": "PCSCF",
            "dest_nf": "UE",
            "interface": "Gm/Mw",
            "procedure": "SIP",
            "details": f"SIP error {i+1}"
        })
    
    return entries

def write_test_file():
    entries = generate_test_data()
    with open(TEST_FILE, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    print(f"[+] Written {len(entries)} test events to {TEST_FILE}")

def start_monitoring():
    subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/agent/stop",
        "-H", "Content-Type: application/json",
        "-H", f"x-api-key: {API_KEY}",
        "-d", "{}"
    ], capture_output=True, text=True)
    time.sleep(1)
    
    result = subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/agent/start",
        "-H", "Content-Type: application/json",
        "-H", f"x-api-key: {API_KEY}",
        "-d", json.dumps({"source": TEST_FILE})
    ], capture_output=True, text=True)
    print("[start_monitoring]", result.stdout.strip())
    return result

def check_status():
    result = subprocess.run([
        "curl", "-s", f"{BASE_URL}/api/agent/status",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    print("[status]", result.stdout.strip())
    return result

def check_history(limit=20):
    result = subprocess.run([
        "curl", "-s", f"{BASE_URL}/api/alerts/history?limit={limit}",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    print("[history]", result.stdout.strip())
    return result

def stop_monitoring():
    result = subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/agent/stop",
        "-H", "Content-Type: application/json",
        "-H", f"x-api-key: {API_KEY}",
        "-d", "{}"
    ], capture_output=True, text=True)
    print("[stop_monitoring]", result.stdout.strip())
    return result

def clear_alerts():
    result = subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/alerts/clear",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    print("[clear_alerts]", result.stdout.strip())
    return result

def cleanup():
    import os
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
        print(f"[+] Removed {TEST_FILE}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_alarms.py <command>")
        print("Commands: setup, start, status, history, stop, clear, cleanup, full")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "setup":
        write_test_file()
    elif cmd == "start":
        start_monitoring()
    elif cmd == "status":
        check_status()
    elif cmd == "history":
        check_history()
    elif cmd == "stop":
        stop_monitoring()
    elif cmd == "clear":
        clear_alerts()
    elif cmd == "cleanup":
        cleanup()
    elif cmd == "full":
        print("=== 5G Core Alert Stream Full Test ===")
        write_test_file()
        time.sleep(1)
        start_monitoring()
        time.sleep(3)
        check_status()
        check_history()
        print("\n=== Clearing alerts ===")
        clear_alerts()
        time.sleep(1)
        check_history()
        print("\n=== Stopping monitoring ===")
        stop_monitoring()
        cleanup()
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()
