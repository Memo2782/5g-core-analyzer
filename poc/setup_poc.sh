#!/bin/bash
# 5G Core Analyzer - POC Environment Setup
# This script sets up a complete demo environment for customer presentations

set -e

echo "========================================="
echo "5G Core Analyzer - POC Setup"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python
echo -e "${BLUE}[1/6] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed."
    exit 1
fi
python3 --version

# Create virtual environment
echo -e "${BLUE}[2/6] Setting up virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

# Install dependencies
echo -e "${BLUE}[3/6] Installing dependencies...${NC}"
./venv/bin/pip install -q -r requirements.txt
echo "Dependencies installed."

# Initialize database
echo -e "${BLUE}[4/6] Initializing database...${NC}"
./venv/bin/python -c "from core.database import init_db; init_db(); print('Database initialized.')"

# Generate sample data
echo -e "${BLUE}[5/6] Generating sample 5G Core traces...${NC}"
./venv/bin/python generar_trazas.py
echo "Sample traces generated in data_samples/"

# Create demo log directory
echo -e "${BLUE}[6/6] Creating demo log directory...${NC}"
mkdir -p /tmp/5g-poc-logs
cat > /tmp/5g-poc-logs/amf.log << 'EOF'
{"timestamp":"2026-08-11T14:00:01Z","source_nf":"AMF","dest_nf":"AUSF","interface":"N12","http_status":"401","details":"Auth handshake failure"}
{"timestamp":"2026-08-11T14:00:02Z","source_nf":"AMF","dest_nf":"UDM","interface":"N8","http_status":"200","details":"Subscription data retrieved"}
{"timestamp":"2026-08-11T14:00:03Z","source_nf":"AMF","dest_nf":"SMF","interface":"N11","http_status":"200","details":"PDU session establishment"}
EOF

cat > /tmp/5g-poc-logs/smf.log << 'EOF'
{"timestamp":"2026-08-11T14:00:01Z","source_nf":"SMF","dest_nf":"UPF","interface":"N4","http_status":"200","details":"PFCP session creation"}
{"timestamp":"2026-08-11T14:00:02Z","source_nf":"SMF","dest_nf":"PCF","interface":"N5","http_status":"404","details":"Policy not found"}
{"timestamp":"2026-08-11T14:00:03Z","source_nf":"SMF","dest_nf":"UPF","interface":"N4","http_status":"504","details":"UPF timeout"}
EOF

cat > /tmp/5g-poc-logs/ims.log << 'EOF'
{"timestamp":"2026-08-11T14:00:01Z","source_nf":"UE","dest_nf":"PCSCF","interface":"Gm","http_status":"100","details":"SIP INVITE received"}
{"timestamp":"2026-08-11T14:00:02Z","source_nf":"PCSCF","dest_nf":"SCSCF","interface":"Mw","http_status":"183","details":"SIP 183 Session Progress"}
{"timestamp":"2026-08-11T14:00:03Z","source_nf":"SCSCF","dest_nf":"TAS","interface":"ISC","http_status":"200","details":"Service triggered"}
EOF

echo "Demo logs created in /tmp/5g-poc-logs/"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}POC Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "To start the POC server:"
echo "  ./venv/bin/python -m uvicorn web_app:app --host 0.0.0.0 --port 8000"
echo ""
echo "Then open in your browser:"
echo "  http://localhost:8000"
echo ""
echo "Demo credentials:"
echo "  1. Register a new tenant at http://localhost:8000 (or use API)"
echo "  2. Upload traces from data_samples/"
echo "  3. Start monitoring: /tmp/5g-poc-logs/"
echo "  4. View real-time alerts at http://localhost:8000/test-websocket"
echo ""
