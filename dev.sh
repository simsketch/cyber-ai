#!/bin/bash

echo "Starting Cyber AI development environment..."

# Start the backend
echo "Starting backend server..."
cd src && python3 -m uvicorn main:app --reload --port 8000 &
cd ..

# Start the frontend
echo "Starting frontend..."
cd frontend && pnpm dev &

# Start the documentation server
# echo "Starting documentation server..."
# cd docs && pnpm start &

# Wait for all background processes
wait 