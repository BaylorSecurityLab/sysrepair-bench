#!/bin/bash
# Verification: Scenario 15 - Exim4 SMTP exposed on all interfaces (CWE-668)
# VulnHub Source: Metasploitable / DC
#
# PoC checks:        no LISTEN socket on port 25 is bound to a wildcard address
# Regression checks: something is still listening on 25 and answers SMTP on
#                    loopback with a 220 greeting
#
# Exit 0 = every check passed          (remediated, MTA still serves locally)
# Exit 1 = at least one check failed
#
# Dynamic evidence WITHOUT curl/ss/netstat (absent in this image): parse
# /proc/net/tcp{,6} for the LIVE listening sockets on port 25 (hex 0019,
# state 0A = LISTEN). This reflects the running daemon, not the config file, so
# a config edit that is never followed by a restart FAILS here. A real SMTP
# banner grab over /dev/tcp confirms the service still works locally.
#
# Two-component protocol: nothing aborts early, so "rebound to loopback but
# killed exim" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT_HEX=0019   # 25

# Collect every LISTEN socket (state 0A) on port 25 from IPv4 + IPv6 tables.
listens() {
    awk -v ph="$PORT_HEX" '
        NR>1 && $4=="0A" {
            n=split($2,a,":");
            if (a[2]==ph) print a[1]
        }' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

MAPPED=$(listens)
echo "  port-25 LISTEN local addresses (hex): ${MAPPED:-<none>}"

# --- Regression: the MTA must still be listening at all ---
if [ -z "$MAPPED" ]; then
    record_reg smtp_listening 0 "nothing is listening on port 25 - exim is down"
else
    record_reg smtp_listening 1
fi

# --- PoC: no wildcard bind. IPv4 "any" = 00000000 ; IPv6 "any" = 32 zero hex chars.
if printf '%s\n' "$MAPPED" | grep -qxE '00000000|0{32}'; then
    record_poc smtp_not_wildcard_bound 0 "exim is LISTENING on all interfaces (0.0.0.0/::), still exposed (did the config change take effect - was exim restarted?)"
else
    record_poc smtp_not_wildcard_bound 1
fi

# Informational only (the original emitted a WARN and could not fail on it).
# IPv4 127.0.0.1 = 0100007F, IPv6 ::1 = 0...01.
if printf '%s\n' "$MAPPED" | grep -qiE '0100007F|0{31}1'; then
    echo "  (note: exim is bound to loopback)"
else
    echo "  WARN: exim not bound to loopback either (bound to a specific non-wildcard addr)."
fi

# --- Regression: real SMTP banner over /dev/tcp (no external tools) ---
BANNER=$(timeout 8 bash -c '
    exec 3<>/dev/tcp/127.0.0.1/25 || exit 1
    IFS= read -r line <&3
    printf "%s" "$line"
    printf "QUIT\r\n" >&3
    exec 3>&-
' 2>/dev/null)
echo "  SMTP banner: ${BANNER:-<none>}"
if printf '%s' "$BANNER" | grep -q '^220'; then
    record_reg smtp_banner_on_loopback 1
else
    record_reg smtp_banner_on_loopback 0 "no 220 SMTP greeting on 127.0.0.1:25 - MTA broken"
fi

verify_finish
