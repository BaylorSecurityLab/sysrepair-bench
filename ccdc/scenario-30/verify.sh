#!/bin/bash
# Scenario 30: fail2ban not installed
# Verification: PoC should fail (fail2ban active) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "installed brute-force protection but blackholed SSH" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TEST_IP="10.88.77.66"

# `pgrep` alone is unsafe here: PID 1 is `sleep infinity` and never reaps
# children, so a dead daemon lingers as a zombie that pgrep still matches.
proc_alive() {
    local p st
    for p in $(pgrep -x "$1" 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# --- PoC Test: fail2ban should be installed ---
if dpkg -l fail2ban 2>/dev/null | grep -q "^ii"; then
    record_poc fail2ban_installed 1
else
    record_poc fail2ban_installed 0 "fail2ban is not installed"
fi

# --- PoC Test: fail2ban should already be running ---
# WAS BROKEN: when fail2ban was not running, verify.sh STARTED IT ITSELF
# (`fail2ban-server -b || fail2ban-client start`) and then reported PASS. That
# masked every solution that installed and configured fail2ban but never
# arranged for it to actually run - the protection would be absent on the real
# host. Verification must observe the system, not repair it.
if proc_alive fail2ban-server; then
    record_poc fail2ban_server_running 1
    F2B_RUNNING=true
else
    record_poc fail2ban_server_running 0 "fail2ban-server is not running (the remediation must arrange for it to be started)"
    F2B_RUNNING=false
fi

# --- PoC Primary Test: fail2ban-client status sshd should show active jail ---
F2B_STATUS=$(fail2ban-client status sshd 2>/dev/null || true)
if echo "$F2B_STATUS" | grep -q "Status for the jail"; then
    record_poc sshd_jail_active 1 "SSH jail is active (fail2ban-client status sshd confirms)"
    JAIL_ACTIVE=true
else
    JAIL_ACTIVE=false
    if [ -f /etc/fail2ban/jail.local ] || [ -f /etc/fail2ban/jail.d/sshd.conf ]; then
        if grep -rqE '^\[sshd\]' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null; then
            record_poc sshd_jail_active 0 "SSH jail is configured but fail2ban-client cannot confirm it is active"
        else
            record_poc sshd_jail_active 0 "SSH jail is not configured in jail files"
        fi
    else
        record_poc sshd_jail_active 0 "no fail2ban jail configuration found and fail2ban-client reports no sshd jail"
    fi
fi

# --- PoC Behavioral Test: the jail must actually BAN a brute-force source ---
# WAS BROKEN: the old script never exercised a ban at all. A jail can be
# "active" and still ban nothing - a wrong logpath, a backend with no journal,
# or a banaction that cannot touch netfilter all leave the host unprotected
# while `fail2ban-client status sshd` looks perfectly healthy.
if [ "$JAIL_ACTIVE" = true ]; then
    fail2ban-client set sshd unbanip "$TEST_IP" > /dev/null 2>&1 || true

    MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null | tr -dc '0-9')
    [ -z "$MAXRETRY" ] && MAXRETRY=5
    LOGFILE=$(echo "$F2B_STATUS" | sed -n 's/.*File list:[[:space:]]*//p' | awk '{print $1}')

    BAN_METHOD=""
    if [ -n "$LOGFILE" ] && { [ ! -e "$LOGFILE" ] || [ ! -w "$LOGFILE" ]; }; then
        # A jail pointed at a log that does not exist can never see a brute
        # force, however healthy `fail2ban-client status` looks.
        record_poc jail_logpath_usable 0 "the sshd jail watches '$LOGFILE', which does not exist or is not writable - it can never observe an SSH brute force"
        LOGFILE=""
    fi
    if [ -n "$LOGFILE" ]; then
        # Drive the REAL detection path: write failed-password lines the sshd
        # filter recognises and wait for fail2ban to react.
        #
        # This is the only place this verifier mutates the box, so undo it from
        # a trap rather than inline: a SIGKILL/timeout mid-probe would otherwise
        # leave forged "Failed password" lines in the box's auth log AND leave
        # $TEST_IP banned in netfilter, so a second run would start from a
        # polluted state and grade differently.
        F2B_LOG_BACKUP=$(mktemp)
        cp -p "$LOGFILE" "$F2B_LOG_BACKUP" 2>/dev/null || : > "$F2B_LOG_BACKUP"
        _f2b_probe_cleanup() {
            fail2ban-client set sshd unbanip "$TEST_IP" > /dev/null 2>&1 || true
            if [ -n "${F2B_LOG_BACKUP:-}" ] && [ -f "$F2B_LOG_BACKUP" ]; then
                # Restore byte-for-byte: drop the forged brute-force lines.
                cp -p "$F2B_LOG_BACKUP" "$LOGFILE" 2>/dev/null
                rm -f "$F2B_LOG_BACKUP" 2>/dev/null
            fi
        }
        trap _f2b_probe_cleanup EXIT INT TERM

        BAN_METHOD="log-driven brute force against $LOGFILE"
        STAMP=$(date '+%b %e %H:%M:%S')
        HOSTN=$(hostname)
        i=0
        while [ "$i" -le "$MAXRETRY" ]; do
            echo "$STAMP $HOSTN sshd[9$i]: Failed password for invalid user hacker from $TEST_IP port 5${i}22 ssh2" >> "$LOGFILE"
            i=$((i + 1))
        done
    else
        # Non-file backend: exercise the ban ACTION directly instead.
        BAN_METHOD="direct banip (jail has no writable log file)"
        fail2ban-client set sshd banip "$TEST_IP" > /dev/null 2>&1 || true
    fi

    BANNED=false
    for _ in $(seq 1 20); do
        if fail2ban-client get sshd banned 2>/dev/null | grep -q "$TEST_IP"; then
            BANNED=true
            break
        fi
        sleep 1
    done

    if [ "$BANNED" = true ]; then
        record_poc jail_bans_brute_force 1 "sshd jail banned $TEST_IP ($BAN_METHOD)"
    else
        record_poc jail_bans_brute_force 0 "sshd jail did NOT ban $TEST_IP ($BAN_METHOD) - the jail is not protecting SSH"
    fi

    # The ban must reach the packet filter, not just fail2ban's own bookkeeping.
    # (fail2ban records the ban before actionban finishes, so poll rather than
    # sampling once.)
    if [ "$BANNED" = true ] && command -v iptables > /dev/null 2>&1; then
        ENFORCED=false
        for _ in $(seq 1 15); do
            if iptables -S 2>/dev/null | grep -q "$TEST_IP"; then
                ENFORCED=true
                break
            fi
            sleep 1
        done
        if [ "$ENFORCED" = true ]; then
            record_poc ban_enforced_in_netfilter 1 "the ban is enforced in netfilter (a rule for $TEST_IP exists)"
        else
            record_poc ban_enforced_in_netfilter 0 "$TEST_IP is banned in fail2ban but no netfilter rule enforces it"
        fi
    fi

    # Leave the box the way we found it: unban AND remove the forged log lines.
    # Runs the same cleanup the trap would, then disarms it.
    if command -v _f2b_probe_cleanup > /dev/null 2>&1 || declare -F _f2b_probe_cleanup > /dev/null 2>&1; then
        _f2b_probe_cleanup
        trap - EXIT INT TERM
    else
        fail2ban-client set sshd unbanip "$TEST_IP" > /dev/null 2>&1 || true
    fi
elif [ "$F2B_RUNNING" = true ]; then
    echo "  [skip] cannot exercise a ban because the sshd jail is not active (already recorded as sshd_jail_active)"
fi

# --- Regression Test: SSH should still be running and reachable ---
# This verifier deliberately does NOT start sshd either. The image CMD boots it
# (see .preserve-cmd), so it is already up when grading starts; starting it here
# would mask an agent that killed SSH - or fire-walled it off with an
# over-broad banaction - while installing brute-force protection.
if proc_alive sshd; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running"
fi

# WAS BROKEN: the regression never touched port 22, so a banaction that
# blackholed all SSH traffic would still have passed. Read the real SSH banner.
SSH_BANNER=$(timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; head -c 40 <&3' 2>/dev/null)
if echo "$SSH_BANNER" | grep -q '^SSH-2.0'; then
    record_reg ssh_banner_on_port22 1 "sshd answers on port 22 (${SSH_BANNER%%$'\r'*})"
else
    record_reg ssh_banner_on_port22 0 "no SSH banner on port 22 (got '${SSH_BANNER:-nothing}')"
fi

if sshd -t 2>/dev/null; then
    record_reg sshd_config_valid 1
else
    record_reg sshd_config_valid 0 "sshd configuration is invalid"
fi

verify_finish
