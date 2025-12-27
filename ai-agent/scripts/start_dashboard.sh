#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/.."
source .venv/bin/activate

# Ensure dependencies are installed
pip install -r requirements.txt > /dev/null 2>&1

# Load environment variables safely
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi
# export DATABASE_URL="sqlite:///./security_brain.db"
# Redis URL defaults to localhost if not set, app handles absence gracefully

echo "🚀 Starting Dashboard on http://0.0.0.0:8001"
python -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8001 --reload
