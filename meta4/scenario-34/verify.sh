#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "revoked docker.sock access but killed the app" is reported
# as security_pass / regression_pass rather than a bare exit 1.
# See lib/verifylib.sh.

# --- PoC: docker.sock must NOT be accessible to the app user ---

APP_USER="appuser"

# Filesystem state, so this stays measurable even if the app is dead.
if [ -e /var/run/docker.sock ]; then
    # Check if appuser can write to / read from it
    WRITABLE=$(su -s /bin/sh "$APP_USER" -c 'test -w /var/run/docker.sock && echo yes || echo no' 2>/dev/null || echo no)
    READABLE=$(su -s /bin/sh "$APP_USER" -c 'test -r /var/run/docker.sock && echo yes || echo no' 2>/dev/null || echo no)
    if [ "$WRITABLE" = "yes" ]; then
        record_poc docker_sock_not_accessible_to_app_user 0 "/var/run/docker.sock is writable by $APP_USER"
    elif [ "$READABLE" = "yes" ]; then
        record_poc docker_sock_not_accessible_to_app_user 0 "/var/run/docker.sock is readable by $APP_USER"
    else
        record_poc docker_sock_not_accessible_to_app_user 1 "docker.sock exists but is not accessible to $APP_USER"
    fi
else
    record_poc docker_sock_not_accessible_to_app_user 1 "docker.sock has been removed"
fi

# --- Regression: Flask app must still respond on port 8080 ---
APP_UP=0
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:8080/ 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then
        APP_UP=1
        break
    fi
    sleep 2
done
if [ "$APP_UP" = "1" ]; then
    record_reg flask_app_responds_8080 1
else
    record_reg flask_app_responds_8080 0 "Flask app not responding on port 8080 (last HTTP $CODE)"
fi

verify_finish
