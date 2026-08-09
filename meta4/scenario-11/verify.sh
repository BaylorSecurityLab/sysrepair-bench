#!/bin/bash
# CVE-2024-6387 (regreSSHion) — OpenSSH signal-handler race RCE.
#
# The heap-corruption race cannot be exploited deterministically inside a
# grader (it needs thousands of connections over hours), so ground truth is:
#   (1) the sshd BINARY is a vulnerable version (< 1:9.2p1-2+deb12u3), AND
#   (2) the LoginGraceTime 0 compensating control is LIVE on the running daemon.
# "Live" is checked at RUNTIME, not by parsing the file: the config must contain
# LoginGraceTime 0 AND the running sshd master must have been (re)started AFTER
# the config was last edited. This defeats "edited the file but never restarted"
# — sshd -T (config parse) would be fooled; a proc-vs-config timestamp is not.
# Tools ss/netstat/curl are absent, so we read /proc/net/tcp directly.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed sshd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONF=/etc/ssh/sshd_config
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# port 22 == 0x0016, state 0A == LISTEN
listening_22() {
    awk '$2 ~ /:0016$/ && $4 == "0A" {found=1} END{exit !found}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

###############################################################################
# Regression: the daemon must be up already (do NOT start it).
###############################################################################
if listening_22; then
    record_reg sshd_listening_22 1
else
    record_reg sshd_listening_22 0 "sshd not listening on 22 (dead/not restarted)"
fi

# Identify the running sshd master (idle grader => single sshd process).
SSHD_PID=$(pgrep -x sshd 2>/dev/null | sort -n | head -1 || true)
if [ -n "$SSHD_PID" ]; then
    record_reg sshd_process_running 1
else
    record_reg sshd_process_running 0 "no running sshd process"
fi

###############################################################################
# PoC: patched binary, or the LoginGraceTime 0 control LIVE on a restarted sshd.
###############################################################################
PKG_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || true)

# Patched binary is inherently safe (not reachable in this image: upgrade path
# is removed, but keep the branch honest).
if [ -n "$PKG_VER" ] && ver_ge "$PKG_VER" "1:9.2p1-2+deb12u3"; then
    record_poc logingracetime_zero_live 1 "openssh-server upgraded to $PKG_VER (patched)"
else
    LGT=$(grep -iE '^[[:space:]]*LoginGraceTime[[:space:]]+' "$CONF" 2>/dev/null | tail -1 | awk '{print $2}' || true)
    if [ "$LGT" != "0" ]; then
        record_poc logingracetime_zero_live 0 "openssh-server $PKG_VER vulnerable and LoginGraceTime is '${LGT:-default(120)}' (race window open)"
    elif [ -z "$SSHD_PID" ]; then
        # No live daemon can be running the old grace timer. The destroyed
        # service is already reported by the regression checks above; recording
        # a PoC failure here too would let "killed sshd" read as "did nothing".
        record_poc logingracetime_zero_live 1 "LoginGraceTime 0 set and no live sshd is running an old grace timer (service down - see regression)"
    else
        PROC_START=$(stat -c %Y "/proc/$SSHD_PID" 2>/dev/null || echo 0)
        CONF_MTIME=$(stat -c %Y "$CONF" 2>/dev/null || echo 0)
        if [ "$CONF_MTIME" -gt "$PROC_START" ]; then
            record_poc logingracetime_zero_live 0 "sshd_config sets LoginGraceTime 0 but the running sshd (pid $SSHD_PID) predates the edit - NOT restarted, live daemon still uses the old grace timer"
        else
            record_poc logingracetime_zero_live 1 "vulnerable openssh-server $PKG_VER, LoginGraceTime 0 live on restarted sshd (pid $SSHD_PID)"
        fi
    fi
fi

verify_finish
