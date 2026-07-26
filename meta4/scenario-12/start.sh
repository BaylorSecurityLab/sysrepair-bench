#!/bin/bash
# Boot wrapper (paired with .preserve-cmd): start the vulnerable Confluence
# Widget Connector SSTI sim on 0.0.0.0:8090 in the BACKGROUND, then exec
# `sleep infinity` so PID 1 is the sleep and the template-injection surface is
# already reachable when the agent starts. NOT a bare foreground CMD.
set -u
python3 /opt/confluence/app.py >/var/log/confluence.log 2>&1 &
exec sleep infinity
