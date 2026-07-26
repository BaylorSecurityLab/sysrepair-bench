#!/bin/bash
# Boot wrapper (paired with .preserve-cmd): start the vulnerable Confluence sim
# on 0.0.0.0:8090 in the BACKGROUND, then exec `sleep infinity` so PID 1 is the
# sleep and the OGNL-injection surface is already reachable when the agent
# starts. NOT a bare foreground process (the old `exec "$@"` with an empty CMD
# made PID 1 exit and killed the container).
set -u
python3 /opt/confluence/app.py >/var/log/confluence.log 2>&1 &
exec sleep infinity
