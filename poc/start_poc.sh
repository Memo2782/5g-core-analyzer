#!/bin/bash
# Quick start POC - one command to run everything

echo "Starting 5G Core Analyzer POC..."
echo ""

# Check if setup has been run
if [ ! -d "venv" ]; then
    echo "First time setup required. Running setup..."
    chmod +x poc/setup_poc.sh
    ./poc/setup_poc.sh
fi

# Start server
echo "Starting server on http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""

./venv/bin/python -m uvicorn web_app:app --host 0.0.0.0 --port 8000
