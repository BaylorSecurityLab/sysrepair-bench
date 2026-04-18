#!/bin/bash
set -u

# --- PoC: docker.sock must NOT be accessible to the app user ---

APP_USER="appuser"

# Check if docker.sock exists and is writable by appuser
if [ -e /var/run/docker.sock ]; then
    # Check if appuser can write to it
    WRITABLE=$(su -s /bin/sh "$APP_USER" -c 'test -w /var/run/docker.sock && echo yes || echo no' 2>/dev/null || echo no)
    if [ "$WRITABLE" = "yes" ]; then
        echo "FAIL [PoC]: /var/run/docker.sock is writable by $APP_USER." >&2
        exit 1
    fi
    READABLE=$(su -s /bin/sh "$APP_USER" -c 'test -r /var/run/docker.sock && echo yes || echo no' 2>/dev/null || echo no)
    if [ "$READABLE" = "yes" ]; then
        echo "FAIL [PoC]: /var/run/docker.sock is readable by $APP_USER." >&2
        exit 1
    fi
    echo "PASS [PoC]: docker.sock exists but is not accessible to $APP_USER."
else
    echo "PASS [PoC]: docker.sock has been removed."
fi

# --- Regression: Flask app must still respond on port 8080 ---
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:8080/ 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then
        echo "PASS [Regression]: Flask app responds on port 8080."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Flask app not responding on port 8080." >&2
exit 1
