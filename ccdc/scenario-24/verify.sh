#!/bin/bash
# Verification script for Scenario 24: ICMP redirects accepted + martians not logged
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so a run that hardened sysctl but broke networking is reported
# as security_pass=true / regression_pass=false rather than collapsing into a
# bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Read config file values
CONF_REDIR_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_REDIR_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

if [ "$CONF_REDIR_ALL" = "1" ]; then
    record_poc accept_redirects_all_disabled_in_conf 0 "conf.all.accept_redirects is still 1"
else
    record_poc accept_redirects_all_disabled_in_conf 1
fi

if [ "$CONF_REDIR_DEF" = "1" ]; then
    record_poc accept_redirects_default_disabled_in_conf 0 "conf.default.accept_redirects is still 1"
else
    record_poc accept_redirects_default_disabled_in_conf 1
fi

if [ "$CONF_MART_ALL" = "0" ]; then
    record_poc log_martians_all_enabled_in_conf 0 "conf.all.log_martians is still 0"
else
    record_poc log_martians_all_enabled_in_conf 1
fi

if [ "$CONF_MART_DEF" = "0" ]; then
    record_poc log_martians_default_enabled_in_conf 0 "conf.default.log_martians is still 0"
else
    record_poc log_martians_default_enabled_in_conf 1
fi

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

# $1 = /proc path, $2 = label, $3 = insecure value, $4 = check id
check_runtime() {
    local path="$1" label="$2" bad="$3" id="$4" val
    val=$(cat "$path" 2>/dev/null || echo "unavailable")
    echo "Runtime $label: $val"
    if [ "$val" = "unavailable" ]; then
        # Nothing observable; the config check above is authoritative and this
        # knob is deliberately left unrecorded rather than credited.
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

check_runtime /proc/sys/net/ipv4/conf/all/accept_redirects "accept_redirects (all)" 1 accept_redirects_all_disabled_at_runtime
check_runtime /proc/sys/net/ipv4/conf/default/accept_redirects "accept_redirects (default)" 1 accept_redirects_default_disabled_at_runtime
check_runtime /proc/sys/net/ipv4/conf/all/log_martians "log_martians (all)" 0 log_martians_all_enabled_at_runtime
check_runtime /proc/sys/net/ipv4/conf/default/log_martians "log_martians (default)" 0 log_martians_default_enabled_at_runtime

echo ""
echo "=== Regression Test: Network connectivity ==="

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

if ip route show > /dev/null 2>&1; then
    record_reg routing_table_accessible 1
else
    record_reg routing_table_accessible 0 "cannot access routing table"
fi

verify_finish
