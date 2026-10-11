#!/bin/bash
echo "🦅 MailHunterPro - Starting Web Dashboard..."
echo "📡 Dashboard: http://localhost:5001"
echo "🔗 API Docs: http://localhost:5001/api/stats"
echo ""
cd "$(dirname "$0")"
pip install flask -q 2>/dev/null
python3 web/server.py
