#!/bin/bash
# Verification script for Scenario 21: Kernel IP forwarding enabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Check sysctl.conf for insecure values
# In Docker, sysctl runtime values may not be writable, so check the config file
CONF_FORWARD=$(grep -E "^\s*net\.ipv4\.ip_forward\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_FORWARD" = "1" ]; then
    echo "FAIL: net.ipv4.ip_forward is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SEND_ALL" = "1" ]; then
    echo "FAIL: net.ipv4.conf.all.send_redirects is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SEND_DEF" = "1" ]; then
    echo "FAIL: net.ipv4.conf.default.send_redirects is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - sysctl values are secure"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# NOTE: In Docker containers, /proc/sys/ may be read-only and reflect
# host kernel values. We check both config AND runtime — fail if EITHER
# shows the insecure value AND the runtime value was actually changeable.
#
# WAS BROKEN: the "is /proc/sys writable?" test was `if sysctl -w key=val`,
# i.e. it trusted sysctl's EXIT CODE. procps prints
#   sysctl: setting key "...", ignoring: Read-only file system
# on stderr and STILL EXITS 0. So the documented "Docker limitation -> WARNING"
# escape hatch was dead code, every unprivileged run took the hard-FAIL branch,
# and this scenario was UNSOLVABLE without --privileged. We now probe real
# writability instead of trusting sysctl, and we do not mutate anything.

# Non-destructive writability probe: -w plus a rewrite of the CURRENT value.
# Returns 0 only if the runtime knob could genuinely be changed.
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

check_runtime /proc/sys/net/ipv4/ip_forward "ip_forward" 1
check_runtime /proc/sys/net/ipv4/conf/all/send_redirects "send_redirects (all)" 1
check_runtime /proc/sys/net/ipv4/conf/default/send_redirects "send_redirects (default)" 1

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists at runtime) - remediation FAILED"
    exit 1
fi

echo ""
echo "=== Regression Test: Network connectivity ==="

# Check that basic networking still functions
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

# Verify iproute2 still works
if ip route show > /dev/null 2>&1; then
    echo "PASS: ip route works"
else
    echo "FAIL: ip route failed"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
