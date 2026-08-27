#!/usr/bin/env bash
# ==============================================================================
# Secure SMTP — Demo & Presentation Launcher
# ==============================================================================
# Launches both the FastAPI backend and Streamlit dashboard with 1 command.
# Seeds sample data if needed.
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️ Secure SMTP — Cryptographic Security Posture Assessment"
echo "======================================================================"

# 1. Activate Virtual Environment
if [ -d ".venv" ]; then
    echo "✓ Activating virtual environment (.venv)..."
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "✓ Activating virtual environment (venv)..."
    source venv/bin/activate
else
    echo "⚠️ No virtual environment found. Using system python3."
fi

# 2. Check/Generate Test PCAPs & Seed Demo Data
echo "✓ Checking demo database (MongoDB)..."
PYTHONPATH=src python scripts/seed_demo_data.py

# 3. Clean up existing processes on ports 8000 and 8501 if any
echo "✓ Checking ports..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:8501 | xargs kill -9 2>/dev/null || true

# 4. Start FastAPI Backend
echo "✓ Starting FastAPI backend on http://localhost:8000..."
PYTHONPATH=src uvicorn securemailscope.api.main:app --host 0.0.0.0 --port 8000 --log-level warning &
BACKEND_PID=$!

# Wait for backend to be ready
echo "✓ Waiting for backend initialization..."
for i in {1..30}; do
    if curl -s http://localhost:8000/api/hosts >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# 5. Start Streamlit Dashboard
echo "✓ Starting Streamlit dashboard on http://localhost:8501..."
PYTHONPATH=src streamlit run dashboard/app.py --server.port 8501 --server.headless false &
FRONTEND_PID=$!

# 6. Presentation Ready Banner
echo ""
echo "======================================================================"
echo "🚀 Secure SMTP is LIVE and ready for presentation!"
echo "======================================================================"
echo "  🌐 Streamlit Dashboard:  http://localhost:8501"
echo "  📡 FastAPI Backend:      http://localhost:8000"
echo "  📚 Swagger API Docs:     http://localhost:8000/docs"
echo "  📁 Demo PCAPs Location:  $PROJECT_ROOT/tests/fixtures/pcaps/"
echo "======================================================================"
echo "Press Ctrl+C to stop all servers."
echo ""

# Trap SIGINT / SIGTERM for clean shutdown
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "✓ All servers stopped. Good luck with the judges!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait on background processes
wait
