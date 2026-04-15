#!/bin/bash
# Entrypoint for scenario-07: ProFTPD 1.3.5 mod_copy (CVE-2015-3306)

# Create proftpd runtime directory if missing
mkdir -p /var/run/proftpd

# Start ProFTPD in foreground (no init system inside Docker)
exec /opt/proftpd/sbin/proftpd --nodaemon
