#!/bin/bash

# Kill background processes when script is terminated
trap 'kill $(jobs -p)' EXIT

# Start the backend server
echo "Starting backend server..."
python src/main.py &

# Start the frontend dev server
echo "Starting frontend..."
cd frontend && npm run dev &

# Start the documentation server
echo "Starting documentation..."
cd docs && npm run start &

# Wait for all background processes
wait 