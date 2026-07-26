#!/bin/bash
# Simple app that loads a database password from a secret source.
# Prefers a restricted runtime-mounted secret (/run/secrets/db_password, root
# only); falls back to the shipped config file. The vulnerability is that the
# shipped /etc/appsecrets/db.conf is world-readable plaintext — remediation is
# to serve the secret from a restricted source and remove the world-readable copy.
set -u

if [ -f /run/secrets/db_password ]; then
    DB_PASSWORD=$(cat /run/secrets/db_password)
elif [ -f /etc/appsecrets/db.conf ]; then
    # shellcheck disable=SC1091
    . /etc/appsecrets/db.conf
fi

echo "App starting..."
echo "Connecting to database (password loaded: ${DB_PASSWORD:+yes})"
echo "App running. PID $$"

# Keep the container alive
exec sleep infinity
