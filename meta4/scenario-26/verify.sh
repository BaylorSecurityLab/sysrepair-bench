#!/bin/bash
# Scenario 26: privileged container + raw docker.sock bind-mount in the app's
# compose file (container escape by design).
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "dropped the privileges but broke the compose file" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CF=/opt/app/docker-compose.yml

if [ -f "$CF" ]; then
    record_poc compose_file_present 1
else
    record_poc compose_file_present 0 "$CF missing"
fi

if [ -f "$CF" ]; then
    # Must not carry privileged: true
    if grep -qE '^[[:space:]]*privileged:[[:space:]]*true' "$CF"; then
        record_poc privileged_flag_removed 0 "compose file still sets 'privileged: true'"
    else
        record_poc privileged_flag_removed 1
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
        record_poc app_docker_sock_unmounted 1
    else
        record_poc app_docker_sock_unmounted 0 "service 'app' still bind-mounts /var/run/docker.sock"
    fi
fi

###############################################################################
# Dynamic check: render the compose file with the real compose engine.
#
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
###############################################################################
RENDER=""
if command -v docker-compose >/dev/null 2>&1; then
    RENDER=$(docker-compose -f "$CF" config 2>/dev/null) || RENDER=""
elif command -v docker >/dev/null 2>&1; then
    RENDER=$(docker compose -f "$CF" config 2>/dev/null) || RENDER=""
fi

if [ -n "$RENDER" ]; then
    record_reg compose_renders 1

    if printf '%s\n' "$RENDER" | grep -qE '^[[:space:]]*privileged:[[:space:]]*true'; then
        record_poc rendered_privileged_removed 0 "rendered compose still enables 'privileged: true'"
    else
        record_poc rendered_privileged_removed 1
    fi

    # docker.sock must not be bind-mounted into the app service. A dedicated
    # socket-proxy service is permitted to carry it, so we scope to `app`.
    if printf '%s\n' "$RENDER" | awk '
        /^[[:space:]]*services:/{in_svc=1; next}
        in_svc && /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/{svc=$1; gsub(/:/,"",svc); in_app=(svc=="app")}
        in_app && /\/var\/run\/docker\.sock/{found=1}
        END{exit(found?1:0)}
    '; then
        record_poc rendered_app_docker_sock_unmounted 1
    else
        record_poc rendered_app_docker_sock_unmounted 0 "rendered compose still mounts /var/run/docker.sock into 'app'"
    fi
elif command -v docker-compose >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then
    # A compose engine exists but the file would not render. The rendered-output
    # PoC checks are left unrecorded rather than credited: nothing was measured.
    record_reg compose_renders 0 "compose file does not render via 'compose config'"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import yaml,sys; yaml.safe_load(open('$CF'))" 2>/dev/null; then
    # Last resort only when no compose engine exists at all: raw YAML sanity.
    record_reg compose_renders 1 "YAML parses (no compose engine to render)"
else
    record_reg compose_renders 0 "compose file does not parse"
fi

verify_finish
