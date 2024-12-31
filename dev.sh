#!/bin/bash

# Get the absolute path of the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Starting Cyber AI development environment..."

# Start the backend with better logging
echo "Starting backend server..."
cd "$SCRIPT_DIR/src" && python3 -m uvicorn main:app --reload --port 8000 --log-level debug > ../backend.log 2>&1 &

# Start the frontend
echo "Starting frontend..."
cd "$SCRIPT_DIR/frontend" && pnpm dev > ../frontend.log 2>&1 &

# Follow the backend logs
tail -f "$SCRIPT_DIR/backend.log"

# Wait for all background processes
wait 