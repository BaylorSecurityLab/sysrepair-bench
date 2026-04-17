#!/bin/bash
set -e

# Start Apache (simulated Cacti backend) on port 8080
service apache2 start || apache2ctl start || true

sleep 2

exec "$@"
