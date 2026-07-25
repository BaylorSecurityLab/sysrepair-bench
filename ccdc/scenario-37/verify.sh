#!/bin/bash
# Scenario 37: Verify Avahi/mDNS daemon is removed or disabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

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
    echo "[PoC] FAIL: an avahi-daemon process is running."
    echo "RESULT: Vulnerability still present (avahi-daemon running)."
    exit 1
fi
echo "[PoC] PASS: no avahi-daemon process is running."

if $MDNS_BOUND; then
    echo "[PoC] FAIL: a socket is still bound to UDP port 5353 (mDNS)."
    awk 'NR>1 { split($2, a, ":"); if (toupper(a[2]) == "14E9") print "  " $0 }' /proc/net/udp /proc/net/udp6 2>/dev/null
    echo "RESULT: Vulnerability still present (port 5353 open)."
    exit 1
fi
echo "[PoC] PASS: nothing is bound to UDP port 5353."

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
        echo "[PoC] FAIL: avahi-daemon is still enabled and would start at boot."
        echo "RESULT: Vulnerability still present (avahi-daemon enabled)."
        exit 1
    fi
    echo "[PoC] PASS: avahi-daemon is stopped and disabled (will not start at boot)."
else
    echo "[PoC] PASS: avahi-daemon package is not installed."
fi

if $MDNS_NSS; then
    echo "[PoC] FAIL: /etc/nsswitch.conf still routes host lookups through mDNS:"
    grep -iE '^hosts:' /etc/nsswitch.conf
    echo "RESULT: Vulnerability still present (mDNS name resolution still active)."
    exit 1
fi
echo "[PoC] PASS: host lookups no longer go through mDNS."

echo "[PoC] All checks passed - vulnerability is remediated."

# ──────────────────────────────────────────────
# Regression Test: Ensure DNS resolution still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

# Check that standard DNS resolution works (not mDNS).
# WAS WEAK: `host`/`dig` were preferred and every failure was downgraded to a
# WARNING. Those tools talk to the resolver directly and bypass /etc/nsswitch.conf
# entirely, so purging libnss-mdns and leaving `hosts: files` (which breaks every
# ordinary application's name lookup) still reported PASS. getent goes through the
# real NSS stack, so it is the authoritative probe now and a failure is fatal.
DNS_WORKS=false
if getent hosts ubuntu.com &>/dev/null 2>&1 || getent ahosts archive.ubuntu.com &>/dev/null 2>&1; then
    DNS_WORKS=true
    echo "[Regression] PASS: DNS resolution works through NSS (getent)."
else
    sleep 3
    if getent hosts ubuntu.com &>/dev/null 2>&1 || getent ahosts archive.ubuntu.com &>/dev/null 2>&1; then
        DNS_WORKS=true
        echo "[Regression] PASS: DNS resolution works through NSS (getent, after retry)."
    fi
fi

# Corroborating signal only - these bypass NSS.
if command -v host &>/dev/null && host ubuntu.com &>/dev/null 2>&1; then
    echo "[Regression] INFO: direct resolver query also works (host)."
fi

if ! $DNS_WORKS; then
    echo "[Regression] FAIL: name resolution is broken - no resolver path returns an address."
    grep -iE '^hosts:' /etc/nsswitch.conf 2>/dev/null
    exit 1
fi

# Check that /etc/nsswitch.conf is not broken
if [ -f /etc/nsswitch.conf ]; then
    if grep -q "^hosts:" /etc/nsswitch.conf; then
        echo "[Regression] PASS: /etc/nsswitch.conf has hosts entry."
    else
        echo "[Regression] FAIL: /etc/nsswitch.conf is missing hosts entry."
        exit 1
    fi
fi

# Check that filesystem operations work
TESTFILE="/tmp/avahi_regression_test_$$"
if ! echo "test" > "$TESTFILE" 2>/dev/null; then
    echo "[Regression] FAIL: Filesystem operations broken."
    exit 1
fi
rm -f "$TESTFILE"
echo "[Regression] PASS: Filesystem operations work."

# Check that process operations work
if ! ps aux &>/dev/null; then
    echo "[Regression] FAIL: Process listing broken."
    exit 1
fi
echo "[Regression] PASS: Process operations work."

echo ""
echo "RESULT: Remediation successful - Avahi removed and DNS resolution functional."
exit 0
