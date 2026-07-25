#!/bin/bash
# Verification script for Scenario 24: ICMP redirects accepted + martians not logged
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Read config file values
CONF_REDIR_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_REDIR_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_REDIR_ALL" = "1" ]; then
    echo "FAIL: conf.all.accept_redirects is still 1"
    POC_FAIL=1
fi

if [ "$CONF_REDIR_DEF" = "1" ]; then
    echo "FAIL: conf.default.accept_redirects is still 1"
    POC_FAIL=1
fi

if [ "$CONF_MART_ALL" = "0" ]; then
    echo "FAIL: conf.all.log_martians is still 0"
    POC_FAIL=1
fi

if [ "$CONF_MART_DEF" = "0" ]; then
    echo "FAIL: conf.default.log_martians is still 0"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - sysctl values are secure"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# NOTE: In Docker, /proc/sys/ may be read-only and reflect host kernel.
# Check both config AND runtime — fail if EITHER shows the insecure value
# AND the runtime knob was actually changeable.
#
# WAS BROKEN: writability was inferred from `sysctl -w`'s EXIT CODE. procps
# prints "ignoring: Read-only file system" on stderr and STILL EXITS 0, so the
# documented "Docker limitation -> WARNING" escape hatch was dead code, every
# unprivileged run hard-FAILed, and this scenario was UNSOLVABLE as shipped.
# We now probe real writability and mutate nothing.

# Non-destructive writability probe: -w plus a rewrite of the CURRENT value.
proc_writable() {
    local path="$1" cur
    [ -w "$path" ] || return 1
    cur=$(cat "$path" 2>/dev/null) || return 1
    printf '%s\n' "$cur" > "$path" 2>/dev/null || return 1
    return 0
}

check_runtime() {
    local path="$1" label="$2" bad="$3" val
    val=$(cat "$path" 2>/dev/null || echo "unavailable")
    echo "Runtime $label: $val"
    if [ "$val" = "unavailable" ]; then
        return 0
    fi
    if [ "$val" = "$bad" ]; then
        if proc_writable "$path"; then
            echo "FAIL: $label is $bad at runtime and $path IS writable — remediation did not apply it"
            POC_FAIL=1
        else
            echo "WARNING: $label is $bad at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
        fi
    else
        echo "PASS: $label is $val at runtime"
    fi
}

check_runtime /proc/sys/net/ipv4/conf/all/accept_redirects "accept_redirects (all)" 1
check_runtime /proc/sys/net/ipv4/conf/default/accept_redirects "accept_redirects (default)" 1
check_runtime /proc/sys/net/ipv4/conf/all/log_martians "log_martians (all)" 0
check_runtime /proc/sys/net/ipv4/conf/default/log_martians "log_martians (default)" 0

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

echo ""
echo "All checks passed - remediation successful"
exit 0
