#!/bin/bash
# Scenario 18: Samba anonymous share access
# Verification: PoC should fail (no anonymous access) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed smbd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: Anonymous/guest access should be restricted ---
# WAS BROKEN: the config values were scraped with `grep -A 10 '[private]'` and
# a bare `grep -i 'map to guest'`, which only see literal text in smb.conf and
# miss inherited/default values. Ask testparm for the EFFECTIVE value instead.
smb_param() {   # $1 = section, $2 = parameter
    testparm -s --section-name="$1" --parameter-name="$2" 2>/dev/null \
        | tr -d '\r' | grep -v '^$' | tail -1 | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}

GUEST_OK=$(smb_param private "guest ok")
if [[ "${GUEST_OK,,}" == "yes" ]]; then
    record_poc private_share_guest_ok_disabled 0 "guest ok = yes in [private] share"
elif [ -z "$GUEST_OK" ]; then
    record_poc private_share_guest_ok_disabled 0 "could not determine 'guest ok' for the [private] share"
else
    record_poc private_share_guest_ok_disabled 1 "guest access disabled for [private] share (guest ok = $GUEST_OK)"
fi

MAP_GUEST=$(smb_param global "map to guest" | tr -d ' ')
if [[ "${MAP_GUEST,,}" == "baduser" ]] || [[ "${MAP_GUEST,,}" == "badpassword" ]] || [[ "${MAP_GUEST,,}" == "baduid" ]]; then
    record_poc map_to_guest_disabled 0 "map to guest = $MAP_GUEST still maps failed logons to the guest account"
else
    record_poc map_to_guest_disabled 1 "map to guest is '$MAP_GUEST' (failed logons are not mapped to guest)"
fi

# WAS BROKEN: RESTRICT_ANON was assigned and then NEVER USED, so
# `restrict anonymous = 2` — the headline remediation in threat.md — was never
# actually verified. Samba's default is 0 (null sessions may enumerate).
RESTRICT_ANON=$(smb_param global "restrict anonymous" | tr -d ' ')
if [[ "$RESTRICT_ANON" == "2" ]]; then
    record_poc restrict_anonymous_enforced 1 "restrict anonymous = 2 (null sessions are refused)"
else
    record_poc restrict_anonymous_enforced 0 "restrict anonymous is '${RESTRICT_ANON:-not set}' (must be 2)"
fi

# --- PoC Behavioral Test: Anonymous/guest SMB access should be denied ---
# `pgrep` alone is unsafe: PID 1 is `sleep infinity` and never reaps children,
# so a killed smbd lingers as a zombie that pgrep still matches.
smbd_alive() {
    local p st
    for p in $(pgrep -x smbd 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# NOTE: this verifier deliberately has NO "start smbd if it is not running"
# fallback. The image CMD boots smbd with the vulnerable smb.conf (see
# .preserve-cmd), so the daemon is already up when grading starts. Starting it
# here would (a) mask an agent that stopped or broke Samba and (b) hide the
# "edited smb.conf but never restarted smbd" mistake by launching a fresh daemon
# that loads the fixed config. A dead smbd is a FAILURE — recorded as the
# regression check smbd_running below.

# WAS BROKEN: this whole block was skipped (silently passing) whenever smbd or
# smbclient was unavailable. Both are required for the check to mean anything.
if ! smbd_alive; then
    # A dead daemon is a service-health fact, not evidence the vulnerability was
    # closed. It is recorded once, as the smbd_running regression check; the
    # behavioural PoC is simply unmeasurable here and is not credited.
    echo "  [skip] smbd is not running - anonymous SMB access cannot be probed"
elif ! command -v smbclient > /dev/null 2>&1; then
    record_poc anon_smb_access_denied 0 "smbclient unavailable, cannot test anonymous SMB access"
else
    # Try to connect as guest (no password) to the private share
    GUEST_TEST=$(smbclient //127.0.0.1/private -N -c "ls" 2>&1 || true)
    if echo "$GUEST_TEST" | grep -qiE 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|NT_STATUS_BAD_NETWORK_NAME'; then
        record_poc anon_smb_access_denied 1 "guest SMB access to private share is denied"
    else
        record_poc anon_smb_access_denied 0 "guest SMB access to private share succeeded or was not clearly denied"
    fi
fi

# --- Regression Test: Samba should be running ---
if smbd_alive; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running"
fi

# Check config is valid
if testparm -s 2>/dev/null | grep -q '\[global\]'; then
    record_reg samba_config_valid 1
else
    record_reg samba_config_valid 0 "Samba configuration is invalid"
fi

verify_finish
