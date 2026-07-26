#!/bin/bash
# .preserve-cmd boot wrapper. Starts VAmPI backgrounded, seeds the SQLite DB
# (so the SQLi/JWT probes have data to hit), then hands PID 1 to `sleep
# infinity` so a remediation restarting the app cannot kill the container.
set -u
cd /app
python serve.py >/tmp/vampi.log 2>&1 &
for i in $(seq 1 30); do
  python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:5000/",timeout=2)' >/dev/null 2>&1 && break
  sleep 1
done
# Populate users (name1/name2/admin) via VAmPI's /createdb bootstrap route.
python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:5000/createdb",timeout=5)' >/dev/null 2>&1 || true
exec sleep infinity
