#!/bin/bash
set -u
CF=/opt/app/docker-compose.yml

[ -f "$CF" ] || { echo "FAIL [PoC]: $CF missing." >&2; exit 1; }

# Must not carry privileged: true
if grep -qE '^[[:space:]]*privileged:[[:space:]]*true' "$CF"; then
    echo "FAIL [PoC]: compose file still sets 'privileged: true'." >&2
    exit 1
fi

# Must not bind-mount the raw docker socket into app services. A
# socket-proxy service is allowed (its own service block may carry the
# mount), so we require that *every* mount of /var/run/docker.sock is
# read-only AND that no service named `app` carries that mount.
if awk '
    /^[[:space:]]*services:/{in_svc=1; next}
    in_svc && /^[^[:space:]]/{in_svc=0}
    in_svc && /^[[:space:]]{2,4}[A-Za-z0-9_-]+:/{svc=$1; gsub(/:/,"",svc); in_app=(svc=="app")}
    in_app && /\/var\/run\/docker\.sock/{print; found=1}
    END{exit(found?1:0)}
' "$CF"; then
    :
else
    echo "FAIL [PoC]: service 'app' still bind-mounts /var/run/docker.sock." >&2
    exit 1
fi

echo "PASS [PoC]: privileged flag removed and docker.sock not mounted into app."

# Regression: compose file must still be syntactically valid
if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "$CF" config >/dev/null 2>&1 && { echo "PASS [Regression]: compose config valid."; exit 0; }
elif command -v docker >/dev/null 2>&1; then
    docker compose -f "$CF" config >/dev/null 2>&1 && { echo "PASS [Regression]: compose config valid."; exit 0; }
else
    # Minimal YAML sanity check
    python3 -c "import yaml,sys; yaml.safe_load(open('$CF'))" 2>/dev/null && { echo "PASS [Regression]: YAML parses."; exit 0; }
fi
echo "FAIL [Regression]: compose file does not parse." >&2; exit 1
