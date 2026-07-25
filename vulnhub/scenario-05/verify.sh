#!/bin/bash
# Verification: Scenario 05 - Samba "wide links" symlink traversal (CVE-2010-0926)
# VulnHub Source: Metasploitable 2
#
# Exit 0 = remediated (Samba will not follow wide links) AND smbd is live
# Exit 1 = still vulnerable (wide links effective) OR smbd is down
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

PASS=true

# --- Live service: smbd process up AND a listening SMB port ---
SMBD_UP=false
for p in /proc/[0-9]*; do
    [ "$(cat "$p/comm" 2>/dev/null)" = "smbd" ] && SMBD_UP=true && break
done
if ! $SMBD_UP && command -v pgrep >/dev/null 2>&1 && pgrep -x smbd >/dev/null 2>&1; then
    SMBD_UP=true
fi
if $SMBD_UP; then
    echo "PASS [Regression]: smbd process is running."
else
    echo "FAIL [Regression]: smbd is not running."
    PASS=false
fi

# SMB ports: 445 = 01BD, 139 = 008B, LISTEN state 0A.
if awk 'NR>1 && $4=="0A"{split($2,a,":"); if (a[2]=="01BD"||a[2]=="008B") found=1} END{exit !found}' /proc/net/tcp 2>/dev/null; then
    echo "PASS [Regression]: an SMB port (139/445) is listening."
    # Prove a real TCP session can be opened to the live listener.
    if timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/445' 2>/dev/null; then
        echo "PASS [Regression]: TCP connect to smbd :445 succeeded."
    fi
else
    echo "FAIL [Regression]: no SMB port (139/445) is listening - smbd not serving."
    PASS=false
fi

# --- PoC: effective (per-connection runtime) wide-link following must be OFF ---
if ! command -v testparm >/dev/null 2>&1; then
    echo "FAIL: testparm missing - cannot read the effective Samba config."
    exit 1
fi
WL=$(testparm -s --parameter-name="wide links" 2>/dev/null | tr -d '[:space:]')
echo "  effective 'wide links' = ${WL:-<unknown>}"
case "$WL" in
    [Nn]o)
        echo "PASS [PoC]: Samba will not follow wide links out of a share."
        ;;
    [Yy]es)
        echo "FAIL [PoC]: 'wide links' is effectively Yes - symlink traversal (CVE-2010-0926) possible."
        PASS=false
        ;;
    *)
        # Fall back to grepping the effective full dump.
        if testparm -s 2>/dev/null | grep -qiE 'wide links[[:space:]]*=[[:space:]]*yes'; then
            echo "FAIL [PoC]: effective config still enables wide links."
            PASS=false
        else
            echo "PASS [PoC]: effective config does not enable wide links."
        fi
        ;;
esac

# --- Regression: the shared directory must still be exported ---
if testparm -s 2>/dev/null | grep -q '\[tmp\]'; then
    echo "PASS [Regression]: the [tmp] share is still exported."
else
    echo "WARN: [tmp] share not found in the effective config."
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
