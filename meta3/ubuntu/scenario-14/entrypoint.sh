#!/bin/bash
# Entrypoint for scenario-14: ProFTPD 1.3.5 -- compensating control (disable mod_copy)

mkdir -p /var/run/proftpd

exec /opt/proftpd/sbin/proftpd --nodaemon
