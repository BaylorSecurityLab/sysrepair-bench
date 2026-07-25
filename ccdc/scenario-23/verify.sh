#!/bin/bash
# Verification script for Scenario 23: SYN cookies disabled + source routing accepted
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Read config file values
CONF_SYNCOOKIES=$(grep -E "^\s*net\.ipv4\.tcp_syncookies\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SRC_ROUTE_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SRC_ROUTE_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_SYNCOOKIES" = "0" ]; then
    echo "FAIL: tcp_syncookies is still 0 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SRC_ROUTE_ALL" = "1" ]; then
    echo "FAIL: conf.all.accept_source_route is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SRC_ROUTE_DEF" = "1" ]; then
    echo "FAIL: conf.default.accept_source_route is still 1 in sysctl.conf"
    POC_FAIL=1
fi

# ADDED: /etc/sysctl.conf is not the only file sysctl reads. A drop-in under
# /etc/sysctl.d/ (or /run/sysctl.d, /usr/lib/sysctl.d) that re-applies the
# insecure value would previously have gone completely unnoticed.
DROPIN_BAD=$(grep -lE "^\s*(net\.ipv4\.tcp_syncookies\s*=\s*0|net\.ipv4\.conf\.(all|default)\.accept_source_route\s*=\s*1)\s*$" \
    /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf 2>/dev/null)
if [ -n "$DROPIN_BAD" ]; then
    echo "FAIL: a sysctl drop-in still applies an insecure value: $DROPIN_BAD"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - sysctl values are secure"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# WAS BROKEN, three ways:
#  1. `sysctl -w` prints "Read-only file system" but STILL EXITS 0, so the
#     `if sysctl -w ...` guard could not distinguish "fixed it" from "could not
#     write it". Writability is now probed with `[ -w /proc/sys/... ]`.
#  2. The old script printed "PASS: tcp_syncookies is 1 at runtime" whenever the
#     value looked good — but in an unprivileged container these are the HOST
#     kernel's defaults (syncookies=1, accept_source_route=0 ship enabled/off on
#     every modern kernel). That "PASS" was evidence of nothing at all, and the
#     check passed for the wrong reason. It is now reported as a NOTE.
#  3. net.ipv4.conf.default.accept_source_route was never checked at runtime.

# Non-destructive writability probe: `[ -w ]` alone can lie on /proc, so also
# rewrite the CURRENT value (a no-op) and see whether the kernel accepts it.
proc_writable() {
    local path="$1" cur
    [ -w "$path" ] || return 1
    cur=$(cat "$path" 2>/dev/null) || return 1
    printf '%s\n' "$cur" > "$path" 2>/dev/null || return 1
    return 0
}

check_runtime() {   # $1 = /proc path, $2 = label, $3 = insecure value
    local path="$1" label="$2" bad="$3" val
    val=$(cat "$path" 2>/dev/null || echo "unavailable")
    echo "Runtime $label: $val"
    if [ "$val" = "unavailable" ]; then
        echo "NOTE: $label is not exposed in this container; the config file check is authoritative"
        return 0
    fi
    if proc_writable "$path"; then
        if [ "$val" = "$bad" ]; then
            echo "FAIL: /proc/sys is writable here and $label is still the insecure value ($val)"
            return 1
        fi
        echo "PASS: $label is $val at runtime (/proc/sys is writable, so this is authoritative)"
    else
        if [ "$val" = "$bad" ]; then
            echo "NOTE: $label is $val at runtime but /proc/sys is read-only (host kernel value); config file check is authoritative"
        else
            echo "NOTE: $label is $val at runtime, but /proc/sys is read-only so this is the HOST kernel's"
            echo "      default, not proof of remediation; the config file check is authoritative"
        fi
    fi
    return 0
}

check_runtime /proc/sys/net/ipv4/tcp_syncookies                    "tcp_syncookies"                 0 || POC_FAIL=1
check_runtime /proc/sys/net/ipv4/conf/all/accept_source_route      "accept_source_route (all)"      1 || POC_FAIL=1
check_runtime /proc/sys/net/ipv4/conf/default/accept_source_route  "accept_source_route (default)"  1 || POC_FAIL=1

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists at runtime) - remediation FAILED"
    exit 1
fi

echo ""
echo "=== Regression Test: Network connectivity ==="

if ip addr show lo > /dev/null 2>&1; then
    echo "PASS: Loopback interface is up"
else
    echo "FAIL: Loopback interface check failed"
    exit 1
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    echo "PASS: Localhost ping works"
else
    echo "FAIL: Localhost ping failed"
    exit 1
fi

if ip route show > /dev/null 2>&1; then
    echo "PASS: Routing table accessible"
else
    echo "FAIL: Cannot access routing table"
    exit 1
fi

# ADDED: hardening that leaves /etc/sysctl.conf unparsable would silently break
# every other setting in the file on the next boot.
SYSCTL_PARSE=$(sysctl -p /etc/sysctl.conf 2>&1)
if echo "$SYSCTL_PARSE" | grep -qiE 'invalid syntax|malformed line|unknown key'; then
    echo "FAIL: /etc/sysctl.conf no longer parses cleanly:"
    echo "$SYSCTL_PARSE" | grep -iE 'invalid syntax|malformed line|unknown key'
    exit 1
fi
echo "PASS: /etc/sysctl.conf parses cleanly"

echo ""
echo "All checks passed - remediation successful"
exit 0
