#!/bin/bash
# Scenario 17: PwnKit - pkexec local privilege escalation (CVE-2021-4034).
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed PwnKit but deleted pkexec" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PK=/usr/bin/pkexec
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SAFE=0
WHY=""
# Path A: setuid bit cleared
if [ -f "$PK" ] && [ ! -u "$PK" ]; then
    WHY="pkexec setuid bit cleared"
    SAFE=1
fi

# Path B: package upgraded
VER=$(dpkg-query -W -f='${Version}' policykit-1 2>/dev/null || true)
if [ -n "$VER" ] && ver_ge "$VER" "0.105-26ubuntu1.3"; then
    WHY="policykit-1 upgraded to $VER"
    SAFE=1
fi

if [ "$SAFE" = "1" ]; then
    record_poc pwnkit_closed 1 "$WHY"
else
    record_poc pwnkit_closed 0 "pkexec setuid bit present and policykit-1 $VER vulnerable"
fi

###############################################################################
# PoC (behavioral): verify pkexec SUID status at runtime via stat.
###############################################################################
if [ -f "$PK" ]; then
    PERMS=$(stat -c '%a' "$PK" 2>/dev/null || true)
    if [ -n "$PERMS" ]; then
        SUID_BAD=0
        # Check if SUID bit is set (4xxx)
        FIRST_DIGIT="${PERMS:0:1}"
        if [ "${#PERMS}" -eq 4 ] && [ "$FIRST_DIGIT" -ge 4 ] 2>/dev/null; then
            # SUID is set — only acceptable if pkg is upgraded
            if [ -z "$VER" ] || ! ver_ge "$VER" "0.105-26ubuntu1.3"; then
                SUID_BAD=1
            fi
        fi
        if [ "$SUID_BAD" = "1" ]; then
            record_poc pkexec_runtime_perms 0 "pkexec has SUID permissions ($PERMS) and pkg not upgraded"
        else
            record_poc pkexec_runtime_perms 1 "pkexec runtime permissions are $PERMS"
        fi
    fi
fi

###############################################################################
# PoC (behavioral live): actually invoke pkexec as the victim user with empty
# argv. On a vulnerable PwnKit build the binary silently drops privileges or
# returns a specific argc==0 error path; on a patched/de-SUID'd build the euid
# of the child process must NOT be 0.
###############################################################################
if id victim >/dev/null 2>&1 && [ -f "$PK" ]; then
    EUID_OUT=$(su - victim -c "exec -a '' $PK 2>/dev/null; id -u" 2>/dev/null | tail -1 || true)
    if [ "$EUID_OUT" = "0" ]; then
        record_poc pkexec_live_no_escalation 0 "pkexec invoked by victim yielded euid=0 (PwnKit still reachable)"
    else
        record_poc pkexec_live_no_escalation 1 "pkexec runtime invocation by victim did not escalate (euid=$EUID_OUT)"
    fi
fi

###############################################################################
# Regression: pkexec binary still exists.
###############################################################################
if [ -f "$PK" ]; then
    record_reg pkexec_binary_present 1
else
    record_reg pkexec_binary_present 0 "pkexec binary missing"
fi

verify_finish
