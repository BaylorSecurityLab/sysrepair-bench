#!/bin/bash
# Simple app that loads a database password from a secret source.
# Prefers a runtime-mounted secret (/run/secrets/db_password); falls back to the
# app.env file. The vulnerability is that the shipped app.env is world-readable
# plaintext — remediation is to serve the secret from a restricted source.
set -u

if [ -f /run/secrets/db_password ]; then
    DB_PASSWORD=$(cat /run/secrets/db_password)
elif [ -f /opt/app/app.env ]; then
    # shellcheck disable=SC1091
    . /opt/app/app.env
fi

echo "App starting..."
echo "Connecting to database (password loaded: ${DB_PASSWORD:+yes})"
echo "App running. PID $$"

# Keep the container alive
exec sleep infinity
