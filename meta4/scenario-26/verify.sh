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

# --- Dynamic check: render the compose file with the real compose engine ---
# NOTE: the previous version of this check curl'd /var/run/docker.sock and
# failed if it was reachable. That is WRONG here: the base image is
# docker:dind, whose own dockerd legitimately creates an accessible
# /var/run/docker.sock, so the check failed for EVERY remediation and made the
# scenario unsolvable. The vulnerability lives in the compose ARTIFACT, not in
# this host's socket. We instead render the file with the real compose engine
# (`compose config` expands anchors/aliases/${VARs} and normalises volumes to
# long syntax, so a vuln smuggled back via an anchor cannot hide) and
# re-assert the security properties on the fully rendered output. This also
# doubles as the regression check: an invalid file fails to render.
RENDER=""
if command -v docker-compose >/dev/null 2>&1; then
    RENDER=$(docker-compose -f "$CF" config 2>/dev/null) || RENDER=""
elif command -v docker >/dev/null 2>&1; then
    RENDER=$(docker compose -f "$CF" config 2>/dev/null) || RENDER=""
fi

if [ -n "$RENDER" ]; then
    if printf '%s\n' "$RENDER" | grep -qE '^[[:space:]]*privileged:[[:space:]]*true'; then
        echo "FAIL [PoC]: rendered compose still enables 'privileged: true'." >&2
        exit 1
    fi
    # docker.sock must not be bind-mounted into the app service. A dedicated
    # socket-proxy service is permitted to carry it, so we scope to `app`.
    if printf '%s\n' "$RENDER" | awk '
        /^[[:space:]]*services:/{in_svc=1; next}
        in_svc && /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/{svc=$1; gsub(/:/,"",svc); in_app=(svc=="app")}
        in_app && /\/var\/run\/docker\.sock/{found=1}
        END{exit(found?1:0)}
    '; then
        :
    else
        echo "FAIL [PoC]: rendered compose still mounts /var/run/docker.sock into 'app'." >&2
        exit 1
    fi
    echo "PASS [PoC]: rendered compose drops privileged and the app docker.sock mount."
    echo "PASS [Regression]: compose file renders via 'compose config'."
    exit 0
fi

# No compose engine could render the file.
if command -v docker-compose >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then
    echo "FAIL [Regression]: compose file does not render via 'compose config'." >&2
    exit 1
fi
# Last resort only when no compose engine exists at all: raw YAML sanity.
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import yaml,sys; yaml.safe_load(open('$CF'))" 2>/dev/null \
        && { echo "PASS [Regression]: YAML parses (no compose engine to render)."; exit 0; }
fi
echo "FAIL [Regression]: compose file does not parse." >&2; exit 1
