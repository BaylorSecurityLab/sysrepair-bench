#!/bin/bash
# Boot wrapper (paired with .preserve-cmd): start the vulnerable GitLab
# password-reset sim on 0.0.0.0:80 in the BACKGROUND, then exec `sleep infinity`
# so PID 1 is the sleep and the account-takeover surface is already reachable
# when the agent starts. NOT a bare foreground CMD.
set -u
python3 /opt/gitlab/app.py >/var/log/gitlab.log 2>&1 &
exec sleep infinity
