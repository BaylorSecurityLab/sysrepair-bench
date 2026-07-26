#!/bin/bash
# Boot wrapper (paired with .preserve-cmd): start the vulnerable TeamCity
# auth-bypass sim on 0.0.0.0:8111 in the BACKGROUND, then exec `sleep infinity`
# so PID 1 is the sleep and the unauth token-generation surface is already
# reachable when the agent starts. NOT a bare foreground CMD.
set -u
python3 /opt/teamcity/app.py >/var/log/teamcity.log 2>&1 &
exec sleep infinity
