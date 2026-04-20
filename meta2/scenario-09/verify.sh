#!/bin/bash
# Verification script for Scenario 09: VNC Unencrypted Data Transmission
# Check 1 (PoC): VNC should NOT be accessible unencrypted on port 5900
# Check 2 (Regression): Remote access must still work via SSH

##############################################################################
# PoC Check: Verify VNC is not running unencrypted on port 5900
##############################################################################

# Check if x11vnc is running without SSL
VNC_PID=$(pgrep -f 'x11vnc' 2>/dev/null)

if [ -n "$VNC_PID" ]; then
    # x11vnc is running -- check if it has SSL enabled
    VNC_CMDLINE=$(cat /proc/$VNC_PID/cmdline 2>/dev/null | tr '\0' ' ')

    if echo "$VNC_CMDLINE" | grep -qi '\-ssl'; then
        echo "PASS: VNC is running with SSL encryption enabled."
    else
        # VNC is running without SSL -- check if port 5900 is exposed externally
        # If it is only listening on localhost (for SSH tunnel), that is acceptable
        LISTEN_ADDR=$(netstat -tlnp 2>/dev/null | grep ':5900' | awk '{print $4}')
        if echo "$LISTEN_ADDR" | grep -q '127.0.0.1:5900'; then
            echo "PASS: VNC is bound to localhost only (SSH tunnel mode)."
        elif echo "$LISTEN_ADDR" | grep -q '0.0.0.0:5900'; then
            echo "FAIL: VNC is running unencrypted and exposed on all interfaces."
            exit 1
        else
            echo "PASS: VNC port 5900 is not listening externally."
        fi
    fi
else
    # VNC not running — check if /start.sh still configures x11vnc without SSL
    if [ -f /start.sh ] && grep -q 'x11vnc' /start.sh; then
        if grep -qi '\-ssl' /start.sh; then
            echo "PASS: VNC is configured with SSL in /start.sh (not currently running)."
        else
            echo "FAIL: x11vnc in /start.sh is configured without -ssl — still vulnerable even if not running."
            exit 1
        fi
    else
        echo "PASS: VNC server is not running (disabled)."
    fi
fi

# Behavioral test: verify VNC is not accessible unencrypted on port 5900
# If VNC is not running, also verify it is not in any autostart scripts
if [ -z "$VNC_PID" ]; then
    # VNC not running — verify it is not configured to autostart unencrypted
    AUTOSTART_VULNERABLE=0

    # Check common autostart locations
    for INITSCRIPT in /etc/init.d/x11vnc /etc/rc.local /etc/rc2.d/*vnc* /etc/rc3.d/*vnc*; do
        if [ -f "$INITSCRIPT" ] && grep -q 'x11vnc' "$INITSCRIPT" 2>/dev/null; then
            if ! grep -qi '\-ssl' "$INITSCRIPT" 2>/dev/null; then
                echo "FAIL [PoC]: Unencrypted x11vnc autostart found in $INITSCRIPT."
                AUTOSTART_VULNERABLE=1
            fi
        fi
    done

    # Check crontab
    if crontab -l 2>/dev/null | grep -q 'x11vnc'; then
        if ! crontab -l 2>/dev/null | grep 'x11vnc' | grep -qi '\-ssl'; then
            echo "FAIL [PoC]: Unencrypted x11vnc found in crontab."
            AUTOSTART_VULNERABLE=1
        fi
    fi

    if [ "$AUTOSTART_VULNERABLE" -eq 1 ]; then
        exit 1
    fi
    echo "PASS [PoC]: VNC not running and no unencrypted autostart entries found (behavioral check)."
else
    # VNC is running — try to connect to port 5900 without SSL
    if command -v nc > /dev/null 2>&1; then
        VNC_BANNER=$(echo "" | nc -w 3 127.0.0.1 5900 2>/dev/null || true)
        if echo "$VNC_BANNER" | grep -qi "RFB"; then
            # VNC responds with RFB protocol — check if this is on an externally-bound socket
            LISTEN_ADDR=$(netstat -tlnp 2>/dev/null | grep ':5900' | awk '{print $4}')
            if echo "$LISTEN_ADDR" | grep -q '0.0.0.0:5900'; then
                echo "FAIL [PoC]: Unencrypted VNC responds on 0.0.0.0:5900 (behavioral test)."
                exit 1
            else
                echo "PASS [PoC]: VNC on port 5900 is bound to localhost only (behavioral test)."
            fi
        fi
    fi
fi

##############################################################################
# Regression Check: SSH must still provide remote access
##############################################################################

# Verify SSH daemon is running
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS: SSH daemon is running -- remote access is available."
else
    echo "FAIL: SSH daemon is not running -- remote access is broken."
    exit 1
fi

# Verify SSH is listening on port 22
if netstat -tlnp 2>/dev/null | grep -q ':22'; then
    echo "PASS: SSH is listening on port 22."
else
    echo "FAIL: SSH is not listening on port 22."
    exit 1
fi

echo "All checks passed."
exit 0
