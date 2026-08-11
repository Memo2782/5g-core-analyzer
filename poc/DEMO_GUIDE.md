# 5G Core Analyzer - POC Demo Guide

## Pre-Demo Setup (5 minutes)

```bash
# 1. Run the setup script
chmod +x poc/setup_poc.sh
./poc/setup_poc.sh

# 2. Start the server
./venv/bin/python -m uvicorn web_app:app --host 0.0.0.0 --port 8000
```

## Demo Flow (15 minutes)

### 1. Introduction (2 min)
- Open http://localhost:8000
- Show the main interface: upload PCAP, view call flows, download Excel
- Explain: "This is a 5G Core and IMS call flow analyzer that works with any vendor"

### 2. Upload & Analyze Traces (5 min)
- Click "Upload" and select files from `data_samples/`
- Show the generated Mermaid call flow diagrams
- Click on nodes to show 3GPP technical details
- Click on error codes (401, 404, 504) to show root cause + solution
- Download Excel report

**Key message:** "Post-mortem analysis of any 5G Core trace, vendor-agnostic"

### 3. Real-Time Monitoring (5 min)
- Open http://localhost:8000/test-websocket in another tab
- Show the WebSocket alert stream
- Start monitoring the demo logs:
  ```bash
  curl -X POST http://localhost:8000/api/agent/start \
    -H "Content-Type: application/json" \
    -d '{"source": "/tmp/5g-poc-logs"}'
  ```
- Append more events to trigger alerts:
  ```bash
  for i in {1..6}; do
    echo "{\"source_nf\":\"SMF\",\"dest_nf\":\"UPF\",\"interface\":\"N11\",\"http_status\":\"504\",\"timestamp\":\"2026-08-11T14:00:0${i}Z\"}" >> /tmp/5g-poc-logs/smf.log
  done
  ```
- Show critical alert appearing in WebSocket
- Show active alerts in the dashboard

**Key message:** "Real-time alert correlation across 5G Core nodes, 24/7 monitoring"

### 4. Multi-Tenant & Billing (3 min)
- Register a new tenant via API:
  ```bash
  curl -X POST http://localhost:8000/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"name":"Telco MX","email":"demo@telcomx.com","plan":"pro"}'
  ```
- Show checkout URL:
  ```bash
  curl "http://localhost:8000/api/billing/checkout?plan=pro" \
    -H "X-API-Key: YOUR_API_KEY"
  ```
- Explain plan limits: Starter (1 site), Pro (5 sites), Enterprise (unlimited)

**Key message:** "Production-ready SaaS with multi-tenant isolation and subscription enforcement"

## Sample Customer Talking Points

### For Telco NOC Managers
- "Reduce MTTR by 60% with automated call flow correlation"
- "Works with Ericsson, Nokia, Huawei - no vendor lock-in"
- "Deploy in your data center or AWS, full control"

### For 5G Consultants
- "Portable analysis tool for customer engagements"
- "Generate professional Excel reports with one click"
- "Real-time monitoring during cutover/upgrade windows"

### For Government Regulators
- "Audit 5G Core compliance across multiple operators"
- "Standardized output regardless of vendor equipment"
- "Historical analysis of signaling traces"

## Pricing Discussion

| Tier | Price | Target Customer |
|------|-------|-----------------|
| Starter | $50/month | Small Telcos, MVNOs, individual consultants |
| Pro | $799/month | Mid-size Telcos, 5G consulting firms |
| Enterprise | $2,499/month | Tier-1 operators, government regulators |
| Perpetual | $2,500 one-time | On-premise deployment, air-gapped networks |

## Technical Architecture

```
5G Core Nodes (Ericsson/Nokia/Huawei)
    ↓ Syslog / REST API / Kafka
Vendor Adapters (normalize to JSON)
    ↓
Log Agent (sliding-window alert rules)
    ↓ PostgreSQL
FastAPI Backend + WebSocket Dashboard
    ↓
NOC Engineers
```

## Next Steps After POC

1. **Connect to real network** - integrate with one vendor's OSS
2. **Customize alert rules** - based on customer's specific KPIs
3. **Deploy in customer environment** - Docker Compose or AWS
4. **Training** - 2-day workshop for NOC team

## Troubleshooting

### Server won't start
```bash
# Check if port 8000 is in use
lsof -i :8000

# Kill existing process
pkill -f "uvicorn web_app:app"

# Restart
./venv/bin/python -m uvicorn web_app:app --host 0.0.0.0 --port 8000
```

### No alerts appearing
```bash
# Check if logs are being read
tail -f /tmp/5g-poc-logs/smf.log

# Verify monitoring is running
curl "http://localhost:8000/api/agent/status" \
  -H "X-API-Key: YOUR_KEY"
```

### Database errors
```bash
# Reinitialize database
./venv/bin/python -c "from core.database import init_db; init_db()"
```
