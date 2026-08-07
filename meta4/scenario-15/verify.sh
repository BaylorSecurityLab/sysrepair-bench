#!/bin/bash
# Scenario 15: Jenkins CLI arbitrary file read (CVE-2024-23897).
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "patched Jenkins but killed the controller" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Discover Jenkins version (from the jenkins.war Manifest or /login header)
VER=$(curl -sI -m 5 http://127.0.0.1:8080/ 2>/dev/null | awk -F': ' 'tolower($1)=="x-jenkins"{gsub(/\r/,"",$2);print $2}' || true)
[ -z "$VER" ] && VER=$(unzip -p /usr/share/jenkins/jenkins.war META-INF/MANIFEST.MF 2>/dev/null | awk -F': ' '/Jenkins-Version/{gsub(/\r/,"",$2);print $2}' || true)

if [ -z "$VER" ]; then
    record_poc jenkins_version_patched 0 "cannot determine Jenkins version"
elif ver_ge "$VER" "2.442" || { [[ "$VER" == 2.426.* ]] && ver_ge "$VER" "2.426.3"; }; then
    record_poc jenkins_version_patched 1 "Jenkins upgraded to $VER"
else
    record_poc jenkins_version_patched 0 "Jenkins $VER is vulnerable (need >= 2.442 or >= 2.426.3)"
fi

###############################################################################
# PoC (behavioral): attempt CLI @file read via /cli endpoint.
# A patched Jenkins disables args4j @-expansion.
#
# Only measurable while the controller answers. If it never does, the service is
# gone, not fixed -- the regression check below reports that; recording a PoC
# result from an unreachable endpoint would let "killed Jenkins" read as "closed
# the file-read".
###############################################################################
for i in $(seq 1 15); do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/login"; then
        CLI_RESP=$(curl -s -m 5 -X POST \
            "http://127.0.0.1:8080/cli?remoting=false" \
            -d '<hudson><command>help @/etc/passwd</command></hudson>' \
            -H 'Content-Type: application/xml' 2>/dev/null || true)
        if echo "$CLI_RESP" | grep -q 'root:'; then
            record_poc cli_at_file_read_blocked 0 "Jenkins CLI @file read returned /etc/passwd content"
        else
            record_poc cli_at_file_read_blocked 1
        fi
        break
    fi
    sleep 2
done

###############################################################################
# Regression: the Jenkins controller must still serve.
###############################################################################
REACH=0
for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/login" && { REACH=1; break; }
    sleep 2
done
if [ "$REACH" = "1" ]; then
    record_reg jenkins_reachable 1
else
    record_reg jenkins_reachable 0 "Jenkins 8080 unreachable"
fi

verify_finish
