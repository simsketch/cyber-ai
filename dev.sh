#!/bin/bash

# Get the absolute path of the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Starting Cyber AI development environment..."

# Start the backend
echo "Starting backend server..."
cd "$SCRIPT_DIR/src" && python3 -m uvicorn main:app --reload --port 8000 &

# Start the frontend
echo "Starting frontend..."
cd "$SCRIPT_DIR/frontend" && NODE_ENV=development pnpm dev &

# Wait for all background processes
wait 