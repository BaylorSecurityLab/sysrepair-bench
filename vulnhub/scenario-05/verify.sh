#!/bin/bash
# Verification: Scenario 05 - Samba "wide links" symlink traversal (CVE-2010-0926)
# VulnHub Source: Metasploitable 2
#
# PoC checks:        the effective (per-connection) `wide links` value is No
# Regression checks: smbd is running and an SMB port is listening
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# IMPORTANT TOOLING NOTE: this Metasploitable 2 image ships NO smbclient (and has
# no working package repo to install one offline), so a wire-level SMB PoC is not
# possible from inside the container. However, smbd on this image FORKS A FRESH
# CHILD PER CLIENT CONNECTION and re-reads smb.conf, so the value testparm
# computes IS exactly what the next attacker connection would get - it is the
# per-connection RUNTIME value, not a stale cached config. We therefore gate on:
#   (1) smbd genuinely LIVE and listening (a dead server is a FAILURE), and
#   (2) the effective `wide links` value smbd serves == No.
# Because the value is re-read per connection there is no "forgot to restart"
# state to distinguish.
#
# Two-component protocol: nothing aborts early, so "disabled wide links but
# killed smbd" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- Regression: smbd process up AND a listening SMB port ---
SMBD_UP=false
for p in /proc/[0-9]*; do
    [ "$(cat "$p/comm" 2>/dev/null)" = "smbd" ] && SMBD_UP=true && break
done
if ! $SMBD_UP && command -v pgrep >/dev/null 2>&1 && pgrep -x smbd >/dev/null 2>&1; then
    SMBD_UP=true
fi
if $SMBD_UP; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running"
fi

# SMB ports: 445 = 01BD, 139 = 008B, LISTEN state 0A.
if awk 'NR>1 && $4=="0A"{split($2,a,":"); if (a[2]=="01BD"||a[2]=="008B") found=1} END{exit !found}' /proc/net/tcp 2>/dev/null; then
    record_reg smb_port_listening 1
    # Informational only (the original could not fail on this).
    if timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/445' 2>/dev/null; then
        echo "  (note: TCP connect to smbd :445 succeeded)"
    fi
else
    record_reg smb_port_listening 0 "no SMB port (139/445) is listening - smbd not serving"
fi

# --- PoC: effective (per-connection runtime) wide-link following must be OFF ---
if ! command -v testparm >/dev/null 2>&1; then
    record_poc wide_links_disabled 0 "testparm missing - cannot read the effective Samba config"
else
    WL=$(testparm -s --parameter-name="wide links" 2>/dev/null | tr -d '[:space:]')
    echo "  effective 'wide links' = ${WL:-<unknown>}"
    case "$WL" in
        [Nn]o)
            record_poc wide_links_disabled 1
            ;;
        [Yy]es)
            record_poc wide_links_disabled 0 "'wide links' is effectively Yes - symlink traversal (CVE-2010-0926) possible"
            ;;
        *)
            # Fall back to grepping the effective full dump.
            if testparm -s 2>/dev/null | grep -qiE 'wide links[[:space:]]*=[[:space:]]*yes'; then
                record_poc wide_links_disabled 0 "effective config still enables wide links"
            else
                record_poc wide_links_disabled 1
            fi
            ;;
    esac

    # Informational only (the original emitted a WARN and could not fail on it).
    if testparm -s 2>/dev/null | grep -q '\[tmp\]'; then
        echo "  (note: the [tmp] share is still exported)"
    else
        echo "  WARN: [tmp] share not found in the effective config."
    fi
fi

verify_finish
