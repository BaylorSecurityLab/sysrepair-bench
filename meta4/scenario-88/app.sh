#!/bin/bash
# Simple app that reads a database password from the environment.
# VULNERABLE: reads DB_PASSWORD from ENV — visible via docker inspect.
set -u

echo "App starting..."
echo "Connecting to database with password: ${DB_PASSWORD:-<not set>}"
echo "App running. PID $$"

# Keep the container alive
exec sleep infinity
