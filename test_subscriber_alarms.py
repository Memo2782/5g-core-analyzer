#!/usr/bin/env python3
"""Test historical alarms with real subscriber identities."""
import json
import subprocess
import sys

API_KEY = "5ga_F1i4N1Wdjnc7iR0rLQMozjXKrbVGgYlcD1r2TnfjZ5w"
BASE_URL = "http://localhost:8000"

def generate_subscriber_events():
    """Generate events for a real subscriber identity."""
    events = []
    base_time = "2026-08-13T18:30:00.000Z"
    
    # SMF timeout burst - 5 failures in 60s
    for i in range(5):
        events.append({
            "timestamp": base_time,
            "http_status": str(503 + (i % 2)),
            "source_nf": "SMF",
            "dest_nf": "UPF",
            "interface": "N11",
            "details": f"PFCP failure {i+1} for subscriber",
            "imsi": "29501677021929425331",
            "msisdn": "524211360966"
        })
    
    # UDM subscription not found - 3 404s in 180s
    for i in range(3):
        events.append({
            "timestamp": base_time,
            "http_status": "404",
            "source_nf": "UDM",
            "dest_nf": "AMF",
            "interface": "N8",
            "details": f"Subscription not found {i+1}",
            "imsi": "29501677021929425331",
            "msisdn": "524211360966"
        })
    
    # PCF session anomaly - 2 failures in 90s
    for i in range(2):
        events.append({
            "timestamp": base_time,
            "http_status": "500",
            "source_nf": "PCF",
            "dest_nf": "AMF",
            "interface": "N5",
            "details": f"Policy failure {i+1}",
            "imsi": "29501677021929425331",
            "msisdn": "524211360966"
        })
    
    return events

def ingest_events(events):
    """Ingest events via API."""
    payload = json.dumps({"events": events})
    result = subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/ingest",
        "-H", "Content-Type: application/json",
        "-H", f"x-api-key: {API_KEY}",
        "-d", payload
    ], capture_output=True, text=True)
    print("[ingest]", result.stdout.strip())
    return result

def check_history(limit=10):
    """Check alert history."""
    result = subprocess.run([
        "curl", "-s", f"{BASE_URL}/api/alerts/history?limit={limit}",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    data = json.loads(result.stdout)
    print(f"[history] Total alerts: {data['total']}")
    for alert in data['alerts']:
        print(f"  - {alert['rule_name']}: IMSI={alert['imsi']}, MSISDN={alert['msisdn']}, Time={alert['timestamp']}")
    return data

def clear_alerts():
    """Clear all alerts."""
    result = subprocess.run([
        "curl", "-s", "-X", "POST", f"{BASE_URL}/api/alerts/clear",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    print("[clear]", result.stdout.strip())
    return result

def main():
    print("=== Historical Alarm Test with Real Subscriber ===")
    print("Subscriber: IMSI=29501677021929425331, MSISDN=524211360966")
    
    print("\n1. Clearing existing alerts...")
    clear_alerts()
    
    print("\n2. Ingesting events for subscriber...")
    events = generate_subscriber_events()
    print(f"   Generated {len(events)} events")
    ingest_events(events)
    
    print("\n3. Checking alert history...")
    check_history(limit=10)
    
    print("\n4. Filtering by IMSI...")
    result = subprocess.run([
        "curl", "-s", f"{BASE_URL}/api/alerts/history?limit=10&imsi=29501677021929425331",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    data = json.loads(result.stdout)
    print(f"   Filtered alerts: {data['total']}")
    for alert in data['alerts']:
        print(f"   - {alert['rule_name']}: MSISDN={alert['msisdn']}, Time={alert['timestamp']}")
    
    print("\n5. Filtering by MSISDN...")
    result = subprocess.run([
        "curl", "-s", f"{BASE_URL}/api/alerts/history?limit=10&msisdn=524211360966",
        "-H", f"x-api-key: {API_KEY}"
    ], capture_output=True, text=True)
    data = json.loads(result.stdout)
    print(f"   Filtered alerts: {data['total']}")
    for alert in data['alerts']:
        print(f"   - {alert['rule_name']}: IMSI={alert['imsi']}, Time={alert['timestamp']}")

if __name__ == "__main__":
    main()
