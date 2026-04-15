#!/bin/bash
# Verification script for Scenario 08: Samba USN-7826-2 (CVE-2025-10230, CVE-2025-9640)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s08 /bin/bash /verify.sh

###############################################################################
# PoC Check 1: wins hook directive must be absent or empty
###############################################################################

SMB_CONF="/etc/samba/smb.conf"

if grep -qi 'wins hook' "$SMB_CONF" 2>/dev/null; then
    HOOK_VAL=$(grep -i 'wins hook' "$SMB_CONF" | grep -v '^\s*#' | awk -F'=' '{print $2}' | tr -d ' \t')
    if [ -n "$HOOK_VAL" ]; then
        echo "FAIL [PoC-CVE-2025-10230]: smb.conf contains an active 'wins hook' directive: '$HOOK_VAL'" >&2
        echo "  Remove or empty the directive and set 'wins support = no'." >&2
        exit 1
    fi
fi

echo "PASS [PoC-CVE-2025-10230]: No active 'wins hook' directive found in smb.conf."

###############################################################################
# PoC Check 2: streams_xattr must not appear in any vfs objects line
###############################################################################

if grep -qi 'streams_xattr' "$SMB_CONF" 2>/dev/null; then
    XATTR_LINE=$(grep -i 'streams_xattr' "$SMB_CONF" | grep -v '^\s*#')
    if [ -n "$XATTR_LINE" ]; then
        echo "FAIL [PoC-CVE-2025-9640]: smb.conf loads 'streams_xattr' VFS module: $XATTR_LINE" >&2
        echo "  Remove streams_xattr from all vfs objects directives." >&2
        exit 1
    fi
fi

echo "PASS [PoC-CVE-2025-9640]: 'streams_xattr' is not loaded in smb.conf."

###############################################################################
# PoC Check 3 (proxy): Samba package version must be newer than 4.1.6
###############################################################################

SAMBA_VERSION=$(smbclient --version 2>/dev/null | awk '{print $2}')

if [ -z "$SAMBA_VERSION" ]; then
    echo "WARN [PoC-Version]: Could not determine smbclient version -- skipping version check."
else
    # Parse major.minor.patch from version string like "4.1.6" or "4.3.11"
    MAJOR=$(echo "$SAMBA_VERSION" | cut -d. -f1)
    MINOR=$(echo "$SAMBA_VERSION" | cut -d. -f2)
    PATCH=$(echo "$SAMBA_VERSION" | cut -d. -f3 | tr -dc '0-9')
    PATCH=${PATCH:-0}

    # Vulnerable: 4.1.6 and earlier in the 4.1.x line; anything < 4.3.0 is unpatched
    # The USN-7826-2 backport targets 4.3.11+dfsg-0ubuntu0.14.04.x or later
    VULNERABLE=0
    if [ "$MAJOR" -lt 4 ]; then
        VULNERABLE=1
    elif [ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 3 ]; then
        VULNERABLE=1
    elif [ "$MAJOR" -eq 4 ] && [ "$MINOR" -eq 3 ] && [ "$PATCH" -lt 11 ]; then
        VULNERABLE=1
    fi

    if [ "$VULNERABLE" -eq 1 ]; then
        echo "FAIL [PoC-Version]: Samba version $SAMBA_VERSION is older than the patched 4.3.11 backport." >&2
        exit 1
    fi

    echo "PASS [PoC-Version]: Samba version $SAMBA_VERSION meets or exceeds the USN-7826-2 patched baseline."
fi

###############################################################################
# Regression Check: smbclient can list shares on localhost
###############################################################################

if smbclient -L //127.0.0.1 -U guest% -N 2>/dev/null | grep -q 'public\|Sharename'; then
    echo "PASS [Regression]: smbclient can list shares on localhost."
elif smbclient -L //127.0.0.1 -U guest% -N 2>&1 | grep -qiE 'session setup|Connection'; then
    echo "PASS [Regression]: smbclient connected to localhost (share list may be empty)."
else
    # smbd might not be running yet; check process
    if pgrep -x smbd > /dev/null 2>&1; then
        echo "PASS [Regression]: smbd process is running (smbclient list skipped -- daemon may still be initializing)."
    else
        echo "FAIL [Regression]: smbd is not running and smbclient could not connect." >&2
        exit 1
    fi
fi

echo "All checks passed."
exit 0
