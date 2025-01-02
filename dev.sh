#!/bin/bash

# Get the absolute path of the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Starting Cyber AI development environment..."

# Start the backend with better logging
echo "Starting backend server..."
cd "$SCRIPT_DIR/backend/src" && python3 -m uvicorn main:app --reload --port 8000 --log-level debug &

# Start the frontend
echo "Starting frontend..."
cd "$SCRIPT_DIR/frontend" && pnpm dev &

# Wait for all background processes
wait 