#!/bin/bash
# Get the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Back to project root
cd "$DIR/.."
echo "📂 Working Directory: $(pwd)"

# Start the AI Agent API Server
source .venv/bin/activate

echo "🚀 Starting Server on http://0.0.0.0:8000"
# Use python -m uvicorn to ensure proper path resolution
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
