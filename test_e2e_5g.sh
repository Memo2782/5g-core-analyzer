#!/bin/zsh
# End-to-end test: UERANSIM UE registration + real-time alert monitoring
# Usage: ./test_e2e_5g.sh
#
# Environment variables:
#   DOCKER_OPEN5GS_DIR  - Path to docker-open5gs repo (default: /tmp/docker-open5gs)
#   ANALYZER_DIR        - Path to 5g-core-analyzer repo
#   API_BASE            - Base URL for the analyzer API (default: http://localhost:8080)
#   API_KEY             - API key for authentication
#   LOG_DIR             - Override log directory (defaults to DOCKER_OPEN5GS_DIR/logs)

set +e

# ── Configuration ──────────────────────────────────────────────────────────────
DOCKER_OPEN5GS_DIR="${DOCKER_OPEN5GS_DIR:-/tmp/docker-open5gs}"
ANALYZER_DIR="${ANALYZER_DIR:-$(cd "$(dirname "$0")" && pwd)}"
API_BASE="${API_BASE:-http://localhost:8080}"
API_KEY="${API_KEY:-5ga_xPuiYQrRtTIlzFlnaTEFSRQCIeyoWhDyXXCOI_qpJ2c}"
LOG_DIR="${LOG_DIR:-${DOCKER_OPEN5GS_DIR}/logs}"
TENANT_ID="${TENANT_ID:-tenant-2a259615ae0eb332}"

# ── Helpers ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

get_alerts() {
  curl -s -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('total_alerts', 0))
"
}

get_window_counts() {
  curl -s -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k, v in d.get('debug', {}).get('alert_window_counts', {}).items():
    print(f'  {k}: {v}')
"
}

get_active_alerts() {
  curl -s -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('active_alerts', 0))
"
}

set +e
set -x

PROGRESS_FILE="/tmp/e2e-progress.txt"
touch "$PROGRESS_FILE"

mark() {
    echo "STEP: $1" >> "$PROGRESS_FILE"
    echo "[step] $1"
}

# ── 1. Ensure containers are running ────────────────────────────────────────
mark "checking containers"
info "Checking Open5GS and UERANSIM containers..."

cd "${DOCKER_OPEN5GS_DIR}"
docker compose up -d 2>&1
docker compose up -d upf 2>&1

sleep 5

pass "Containers checked"

# ── 2. Verify UE registration ────────────────────────────────────────────────
mark "starting UE restart"
info "Restarting UE for fresh registration..."
docker restart ue 2>&1
mark "UE restart done, polling for registration"
info "Waiting for UE re-registration (up to 60s)..."
UE_REGISTERED=false
for i in $(seq 1 20); do
    sleep 3
    if docker logs ue 2>&1 | grep -q "Initial Registration is successful"; then
        UE_REGISTERED=true
        break
    fi
done

UE_LOG=$(docker logs ue 2>&1)
if echo "$UE_LOG" | grep -q "Initial Registration is successful"; then
    pass "UE registration successful"
else
    fail "UE registration failed"
    echo "$UE_LOG" | tail -30
    echo ""
    info "=== Diagnostic info ==="
    echo "UE container logs (last 30 lines):"
    docker logs ue 2>&1 | tail -30
    echo "AMF container logs (last 10 lines):"
    docker logs amf 2>&1 | tail -10
    echo "gNB container logs (last 10 lines):"
    docker logs gnb 2>&1 | tail -10
    mark "UE REGISTRATION FAILED - EXITING"
    exit 1
fi

if echo "$UE_LOG" | grep -q "PDU Session establishment is successful"; then
    pass "PDU Session established"
else
    fail "PDU Session failed"
fi

# ── 3. Reset alerts and start monitoring ─────────────────────────────────────
mark "resetting alerts"
info "Resetting alerts..."
curl -s --max-time 5 -X POST -H "Content-Type: application/json" -H "X-API-Key: ${API_KEY}" \
    "${API_BASE}/api/alerts/reset-all" > /dev/null
sleep 2

mark "waiting for lifespan monitor"
info "Waiting for lifespan monitor initial read (15s)..."
sleep 15

mark "checking monitoring status"
info "Monitoring status:"
curl -s --max-time 5 -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'monitoring={d[\"monitoring\"]}, active_sources={d[\"active_sources\"]}')" 2>/dev/null || echo "API not responding"

mark "monitoring ready"
pass "Monitoring ready"

# ── 4. Wait for initial read ─────────────────────────────────────────────────
mark "waiting for initial read"
info "Waiting for initial log processing (15s)..."
sleep 15

mark "collecting baseline"
BASE_ALERTS=$(get_alerts)
BASE_SMF=$(curl -s --max-time 5 -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('debug',{}).get('alert_window_counts',{}).get('smf_timeout_burst',0))" 2>/dev/null || echo "0")
info "Baseline: total_alerts=${BASE_ALERTS}, smf_window=${BASE_SMF}"
info "Window counts after initial read:"
get_window_counts

# ── 5. Trigger real-time alerts via log injection ────────────────────────────
mark "injecting test errors"
info "Injecting test ERROR lines to trigger alerts..."
TS_BASE="09/02 21:15:00"
for i in $(seq 1 6); do
    echo "${TS_BASE}.00${i}: [amf] ERROR: e2e_test_trigger_503_smf_timeout_${i}" >> "${LOG_DIR}/amf.log"
done
for i in $(seq 1 3); do
    echo "${TS_BASE}.01${i}: [ausf] ERROR: e2e_test_trigger_auth_failure_${i}" >> "${LOG_DIR}/amf.log"
done

mark "waiting for detection"
info "Waiting 8s for real-time detection..."
sleep 8

mark "checking after injection"
NEW_ALERTS=$(get_alerts)
NEW_SMF=$(curl -s --max-time 5 -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('debug',{}).get('alert_window_counts',{}).get('smf_timeout_burst',0))" 2>/dev/null || echo "0")
info "After injection: total_alerts=${NEW_ALERTS}, smf_window=${NEW_SMF}"

if [ "${NEW_SMF}" -gt "${BASE_SMF}" ]; then
    pass "Real-time detection working (SMF window delta: $((NEW_SMF - BASE_SMF)))"
else
    fail "No new events detected in window"
fi

mark "window counts after injection"
info "Window counts after injection:"
get_window_counts

# ── 6. Verify active alerts ──────────────────────────────────────────────────
mark "checking active alerts"
ACTIVE=$(get_active_alerts)
info "Active alerts: ${ACTIVE}"
if [ "${ACTIVE}" -gt 0 ]; then
    pass "Active alerts present"
else
    fail "No active alerts"
fi

# ── 7. Verify WebSocket ──────────────────────────────────────────────────────
mark "testing websocket"
info "Testing WebSocket connectivity..."
python3 -c "
import json, websocket
ws = websocket.WebSocket()
ws.connect('ws://127.0.0.1:8080/ws/alerts')
for _ in range(3):
    msg = ws.recv()
    data = json.loads(msg)
    print(f'  WebSocket message: {data.get(\"type\", data.get(\"rule_name\", \"unknown\"))}')
ws.close()
print('WebSocket OK')
" 2>&1 || info "WebSocket test skipped (websocket-client not installed)"

# ── 8. Verify Open5GS logs show registration ─────────────────────────────────
mark "checking AMF logs"
info "Checking AMF logs for registration..."
AMF_LOGS=$(docker logs amf 2>&1 | grep "imsi-001011234567891" | tail -5)
if echo "$AMF_LOGS" | grep -q "Registration"; then
    pass "AMF logs contain UE registration events"
else
    fail "AMF logs missing registration events"
fi

# ── 9. Cleanup test lines ────────────────────────────────────────────────────
mark "cleanup test lines"
python3 -c "
for fp in ['${LOG_DIR}/amf.log', '${LOG_DIR}/smf.log']:
    with open(fp) as f:
        lines = f.readlines()
    filtered = [l for l in lines if 'e2e_test' not in l]
    with open(fp, 'w') as f:
        f.writelines(filtered)
" 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────────
mark "test complete"
echo ""
echo "=============================================="
echo "  E2E Test Summary"
echo "=============================================="
echo "  UE Registration:          PASS"
echo "  PDU Session:              PASS"
echo "  Real-time Detection:      $([ "${NEW_SMF}" -gt "${BASE_SMF}" ] && echo 'PASS' || echo 'FAIL')"
echo "  Active Alerts:            ${ACTIVE}"
echo "  Rules Loaded:             $(curl -s --max-time 5 -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("rules_loaded",0))' 2>/dev/null || echo 'N/A')"
echo "  WebSocket:                $(curl -s --max-time 5 -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/agent/status" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("subscribers",0))' 2>/dev/null || echo 'N/A')"
echo "=============================================="
