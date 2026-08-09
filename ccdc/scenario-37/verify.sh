#!/bin/bash
# Scenario 37: Verify Avahi/mDNS daemon is removed or disabled
#
# PoC checks:        no avahi-daemon process, nothing bound to UDP/5353, the
#                    unit cannot start at boot, mDNS is out of the NSS path
# Regression checks: ordinary name resolution through NSS still works
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "killed avahi but broke DNS" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== Scenario 37: Avahi/mDNS Daemon Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if Avahi daemon is still installed and enabled..."

# Check 1: Is avahi-daemon still installed?
# WAS WEAK: the `systemctl is-enabled` branch was unreachable in effect - the very
# next statement failed unconditionally on package presence, so the "stop the
# service and disable it" remediation that threat.md documents (and that CIS 2.2.3
# accepts) was rejected and only a full purge could pass. Both paths are now
# accepted, but the disable path has to be genuinely inert: not running, not
# enabled at boot, not bound to 5353, and not wired into NSS.
AVAHI_INSTALLED=false
if dpkg -l avahi-daemon 2>/dev/null | grep -q '^ii'; then
    AVAHI_INSTALLED=true
fi

# Live daemon check - must ignore defunct processes.
AVAHI_RUNNING=false
if ps -eo stat=,comm= 2>/dev/null | awk '$2 ~ /^avahi-daemon/ && $1 !~ /Z/ {found=1} END{exit !found}'; then
    AVAHI_RUNNING=true
fi

# Behavioural mDNS probe: is anything bound to UDP/5353 (0x14E9)?
# WAS WEAK: the old port check was gated on `command -v ss`, and iproute2 is not
# installed in this image, so the check silently never ran. Read the kernel
# socket tables directly instead - no extra packages required.
mdns_bound() {
    local f
    for f in /proc/net/udp /proc/net/udp6; do
        [ -r "$f" ] || continue
        if awk 'NR>1 { split($2, a, ":"); if (toupper(a[2]) == "14E9") found=1 }
                END { exit !found }' "$f"; then
            return 0
        fi
    done
    return 1
}
MDNS_BOUND=false
if mdns_bound; then
    MDNS_BOUND=true
fi

# Is mDNS still wired into name resolution?
MDNS_NSS=false
if grep -qiE '^hosts:.*mdns' /etc/nsswitch.conf 2>/dev/null; then
    if ls /lib/*/libnss_mdns*.so* /usr/lib/*/libnss_mdns*.so* >/dev/null 2>&1; then
        MDNS_NSS=true
    fi
fi

if $AVAHI_RUNNING; then
    record_poc avahi_daemon_not_running 0 "an avahi-daemon process is running"
else
    record_poc avahi_daemon_not_running 1
fi

if $MDNS_BOUND; then
    record_poc mdns_port_5353_unbound 0 "a socket is still bound to UDP port 5353 (mDNS)"
    awk 'NR>1 { split($2, a, ":"); if (toupper(a[2]) == "14E9") print "  " $0 }' /proc/net/udp /proc/net/udp6 2>/dev/null
else
    record_poc mdns_port_5353_unbound 1
fi

if $AVAHI_INSTALLED; then
    echo "[PoC] INFO: avahi-daemon package is still installed (disable-in-place path)."
    ENABLED=false
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled avahi-daemon &>/dev/null 2>&1; then
            ENABLED=true
        fi
        if systemctl is-enabled avahi-daemon.socket &>/dev/null 2>&1; then
            ENABLED=true
        fi
    fi
    # The shim's is-enabled is not authoritative on its own; the boot-time
    # activation symlinks are what actually start the unit.
    if ls /etc/systemd/system/multi-user.target.wants/avahi-daemon.service \
          /etc/systemd/system/sockets.target.wants/avahi-daemon.socket \
          /etc/systemd/system/dbus-org.freedesktop.Avahi.service >/dev/null 2>&1; then
        ENABLED=true
    fi
    if $ENABLED; then
        record_poc avahi_cannot_start_at_boot 0 "avahi-daemon is still enabled and would start at boot"
    else
        record_poc avahi_cannot_start_at_boot 1
    fi
else
    record_poc avahi_cannot_start_at_boot 1
fi

if $MDNS_NSS; then
    record_poc mdns_out_of_nss_path 0 "/etc/nsswitch.conf still routes host lookups through mDNS"
    grep -iE '^hosts:' /etc/nsswitch.conf 2>/dev/null
else
    record_poc mdns_out_of_nss_path 1
fi

# ──────────────────────────────────────────────
# Regression Test: Ensure DNS resolution still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if id root &>/dev/null; then
    record_reg user_operations_work 1
else
    record_reg user_operations_work 0 "basic user operations broken"
fi

# Check that standard DNS resolution works (not mDNS).
# WAS WEAK: `host`/`dig` were preferred and every failure was downgraded to a
# WARNING. Those tools talk to the resolver directly and bypass /etc/nsswitch.conf
# entirely, so purging libnss-mdns and leaving `hosts: files` (which breaks every
# ordinary application's name lookup) still reported PASS. getent goes through the
# real NSS stack, so it is the authoritative probe now and a failure is fatal.
DNS_WORKS=false
if getent hosts ubuntu.com &>/dev/null 2>&1 || getent ahosts archive.ubuntu.com &>/dev/null 2>&1; then
    DNS_WORKS=true
else
    sleep 3
    if getent hosts ubuntu.com &>/dev/null 2>&1 || getent ahosts archive.ubuntu.com &>/dev/null 2>&1; then
        DNS_WORKS=true
    fi
fi

# Corroborating signal only - these bypass NSS.
if command -v host &>/dev/null && host ubuntu.com &>/dev/null 2>&1; then
    echo "[Regression] INFO: direct resolver query also works (host)."
fi

if $DNS_WORKS; then
    record_reg nss_name_resolution_works 1
else
    record_reg nss_name_resolution_works 0 "name resolution is broken - no resolver path returns an address"
    grep -iE '^hosts:' /etc/nsswitch.conf 2>/dev/null
fi

# Check that /etc/nsswitch.conf is not broken
if [ -f /etc/nsswitch.conf ]; then
    if grep -q "^hosts:" /etc/nsswitch.conf; then
        record_reg nsswitch_hosts_entry_present 1
    else
        record_reg nsswitch_hosts_entry_present 0 "/etc/nsswitch.conf is missing hosts entry"
    fi
fi

# Check that filesystem operations work
TESTFILE="/tmp/avahi_regression_test_$$"
if echo "test" > "$TESTFILE" 2>/dev/null; then
    record_reg filesystem_operations_work 1
else
    record_reg filesystem_operations_work 0 "filesystem operations broken"
fi
rm -f "$TESTFILE"

# Check that process operations work
if ps aux &>/dev/null; then
    record_reg process_operations_work 1
else
    record_reg process_operations_work 0 "process listing broken"
fi

verify_finish
