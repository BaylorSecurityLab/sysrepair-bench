#!/bin/bash
# Verification script for Scenario 21: Kernel IP forwarding enabled
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so a run that hardened sysctl.conf but broke networking is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Check sysctl.conf for insecure values
# In Docker, sysctl runtime values may not be writable, so check the config file
CONF_FORWARD=$(grep -E "^\s*net\.ipv4\.ip_forward\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

if [ "$CONF_FORWARD" = "1" ]; then
    record_poc ip_forward_disabled_in_conf 0 "net.ipv4.ip_forward is still 1 in sysctl.conf"
else
    record_poc ip_forward_disabled_in_conf 1
fi

if [ "$CONF_SEND_ALL" = "1" ]; then
    record_poc send_redirects_all_disabled_in_conf 0 "net.ipv4.conf.all.send_redirects is still 1 in sysctl.conf"
else
    record_poc send_redirects_all_disabled_in_conf 1
fi

if [ "$CONF_SEND_DEF" = "1" ]; then
    record_poc send_redirects_default_disabled_in_conf 0 "net.ipv4.conf.default.send_redirects is still 1 in sysctl.conf"
else
    record_poc send_redirects_default_disabled_in_conf 1
fi

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
    local path="$1" label="$2" bad="$3" id="$4" val
    val=$(cat "$path" 2>/dev/null || echo "unavailable")
    echo "Runtime $label: $val"
    if [ "$val" = "unavailable" ]; then
        # Nothing observable here; the config check above is authoritative and
        # this knob is deliberately left unrecorded rather than credited.
        return 0
    fi
    if [ "$val" = "$bad" ]; then
        if proc_writable "$path"; then
            record_poc "$id" 0 "$label is $bad at runtime and $path IS writable - remediation did not apply it"
        else
            record_poc "$id" 1 "$label is $bad at runtime but /proc/sys is read-only (Docker limitation - config file check is authoritative)"
        fi
    else
        record_poc "$id" 1 "$label is $val at runtime"
    fi
}

check_runtime /proc/sys/net/ipv4/ip_forward "ip_forward" 1 ip_forward_disabled_at_runtime
check_runtime /proc/sys/net/ipv4/conf/all/send_redirects "send_redirects (all)" 1 send_redirects_all_disabled_at_runtime
check_runtime /proc/sys/net/ipv4/conf/default/send_redirects "send_redirects (default)" 1 send_redirects_default_disabled_at_runtime

echo ""
echo "=== Regression Test: Network connectivity ==="

# Check that basic networking still functions
if ip addr show lo > /dev/null 2>&1; then
    record_reg loopback_up 1
else
    record_reg loopback_up 0 "loopback interface check failed"
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    record_reg localhost_ping 1
else
    record_reg localhost_ping 0 "localhost ping failed"
fi

# Verify iproute2 still works
if ip route show > /dev/null 2>&1; then
    record_reg ip_route_works 1
else
    record_reg ip_route_works 0 "ip route failed"
fi

verify_finish
