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
set -u
CONF=/etc/ssh/sshd_config
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# port 22 == 0x0016, state 0A == LISTEN
listening_22() {
    awk '$2 ~ /:0016$/ && $4 == "0A" {found=1} END{exit !found}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# --- daemon must be up already (do NOT start it) -----------------------------
if ! listening_22; then
    echo "FAIL [Regression]: sshd not listening on 22 (dead/not restarted)." >&2
    exit 1
fi

PKG_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || true)

# Patched binary is inherently safe (not reachable in this image: upgrade path
# is removed, but keep the branch honest).
if [ -n "$PKG_VER" ] && ver_ge "$PKG_VER" "1:9.2p1-2+deb12u3"; then
    echo "PASS [PoC]: openssh-server upgraded to $PKG_VER (patched)."
    echo "PASS [Regression]: sshd listening on 22."
    exit 0
fi

# --- vulnerable binary: require the LoginGraceTime 0 control to be LIVE -------
LGT=$(grep -iE '^[[:space:]]*LoginGraceTime[[:space:]]+' "$CONF" 2>/dev/null | tail -1 | awk '{print $2}')
if [ "$LGT" != "0" ]; then
    echo "FAIL [PoC]: openssh-server $PKG_VER vulnerable and LoginGraceTime is '${LGT:-default(120)}' (race window open)." >&2
    exit 1
fi

# Identify the running sshd master (idle grader => single sshd process).
SSHD_PID=$(pgrep -x sshd 2>/dev/null | sort -n | head -1)
if [ -z "$SSHD_PID" ]; then
    echo "FAIL [Regression]: no running sshd process." >&2
    exit 1
fi

PROC_START=$(stat -c %Y "/proc/$SSHD_PID" 2>/dev/null || echo 0)
CONF_MTIME=$(stat -c %Y "$CONF" 2>/dev/null || echo 0)
if [ "$CONF_MTIME" -gt "$PROC_START" ]; then
    echo "FAIL [PoC]: sshd_config sets LoginGraceTime 0 but the running sshd (pid $SSHD_PID) predates the edit — NOT restarted, live daemon still uses the old grace timer." >&2
    exit 1
fi

echo "PASS [PoC]: vulnerable openssh-server $PKG_VER, LoginGraceTime 0 live on restarted sshd (pid $SSHD_PID)."
echo "PASS [Regression]: sshd listening on 22."
exit 0
