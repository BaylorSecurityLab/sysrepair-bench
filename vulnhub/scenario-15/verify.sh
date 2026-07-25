#!/bin/bash
# Verification: Scenario 15 - Exim4 SMTP exposed on all interfaces (CWE-668)
# VulnHub Source: Metasploitable / DC
#
# Exit 0 = remediated (SMTP no longer listens on 0.0.0.0 but still serves local)
# Exit 1 = still vulnerable (listening on all interfaces) OR MTA is dead
#
# Dynamic evidence WITHOUT curl/ss/netstat (absent in this image): parse
# /proc/net/tcp{,6} for the LIVE listening sockets on port 25 (hex 0019,
# state 0A = LISTEN). This reflects the running daemon, not the config file, so
# a config edit that is never followed by a restart FAILS here. A real SMTP
# banner grab over /dev/tcp confirms the service still works locally.

PASS=true
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

if [ -z "$MAPPED" ]; then
    echo "FAIL [Regression]: nothing is listening on port 25 - exim is down."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# IPv4 "any" = 00000000 ; IPv6 "any" = 32 zero hex chars.
if printf '%s\n' "$MAPPED" | grep -qxE '00000000|0{32}'; then
    echo "FAIL [PoC]: exim is LISTENING on all interfaces (0.0.0.0/::), still exposed."
    echo "            (did the config change take effect - was exim restarted?)"
    PASS=false
else
    echo "PASS [PoC]: exim is not listening on any wildcard address."
fi

# Must still serve loopback: IPv4 127.0.0.1 = 0100007F, IPv6 ::1 = 0...01.
if printf '%s\n' "$MAPPED" | grep -qiE '0100007F|0{31}1'; then
    echo "PASS [Regression]: exim is bound to loopback."
else
    echo "WARN: exim not bound to loopback either (bound to a specific non-wildcard addr)."
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
    echo "PASS [Regression]: exim answers SMTP on loopback (220 greeting)."
else
    echo "FAIL [Regression]: no 220 SMTP greeting on 127.0.0.1:25 - MTA broken."
    PASS=false
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
