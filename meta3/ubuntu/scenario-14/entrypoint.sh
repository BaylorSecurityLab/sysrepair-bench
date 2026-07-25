#!/bin/bash
# Boot wrapper (kept via .preserve-cmd): start ProFTPD (which daemonizes/forks to
# the background by default), then hand PID 1 to `sleep infinity` so an agent can
# restart the daemon without killing the container -- making "added CopyEngine
# off but never restarted" detectable.
mkdir -p /var/run/proftpd
/opt/proftpd/sbin/proftpd
exec sleep infinity
