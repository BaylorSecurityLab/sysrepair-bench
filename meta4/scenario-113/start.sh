#!/bin/bash
set -e

# Start simulated Confluence on port 8090
python3 /opt/confluence/app.py &

# Wait for app to start
sleep 2

exec "$@"
