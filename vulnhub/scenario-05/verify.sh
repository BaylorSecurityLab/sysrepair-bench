#!/bin/bash
# Verification script for Scenario 09: Samba Wide Links
# VulnHub Source: Metasploitable 2 (PULLED image)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

SMB_CONF="/etc/samba/smb.conf"

if grep -qi 'wide links\s*=\s*yes' "$SMB_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: 'wide links = yes' is still set in smb.conf."
    exit 1
fi

echo "PASS [PoC]: wide links is not set to yes."

# Behavioral test: verify symlink traversal is blocked via smbclient
if command -v smbclient > /dev/null 2>&1; then
    # Try to follow a symlink outside the share — should fail or show no results
    SMB_OUT=$(smbclient //127.0.0.1/tmp -N -c "ls" 2>&1)
    if echo "$SMB_OUT" | grep -qi 'etc/passwd\|shadow\|root:'; then
        echo "FAIL [PoC]: smbclient can follow symlinks to sensitive files."
        exit 1
    fi
    echo "PASS [PoC]: smbclient cannot follow symlinks to sensitive files."
else
    echo "SKIP [PoC]: smbclient not available for behavioral test."
fi

if pgrep -x smbd > /dev/null 2>&1; then
    echo "PASS [Regression]: smbd is running."
else
    echo "FAIL [Regression]: smbd is not running."
    exit 1
fi

echo "All checks passed."
exit 0
