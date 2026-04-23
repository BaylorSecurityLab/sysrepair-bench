#!/bin/bash
# Scenario 35: Verify NFS server is removed or properly secured
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 35: NFS Server Exposure Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if NFS is insecurely exposed..."

# Path A: NFS has been completely removed (preferred for unnecessary service)
NFS_INSTALLED=false
if dpkg -l nfs-kernel-server 2>/dev/null | grep -q '^ii'; then
    NFS_INSTALLED=true
fi

if ! $NFS_INSTALLED; then
    echo "[PoC] PASS: nfs-kernel-server has been removed entirely."
    echo "[PoC] All checks passed - NFS vulnerability remediated (service removed)."
else
    echo "[PoC] INFO: nfs-kernel-server is still installed, checking configuration..."

    # Path B: NFS still installed - verify it is properly secured

    # Check 1: Is NFS enabled?
    NFS_ENABLED=false
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled nfs-kernel-server &>/dev/null 2>&1; then
            NFS_ENABLED=true
        fi
    fi

    # Check 2: Are exports insecure?
    INSECURE_EXPORTS=false
    if [ -f /etc/exports ]; then
        # Check for wildcard exports
        if grep -qE '^\s*/' /etc/exports 2>/dev/null; then
            # Check for wildcard (*) host
            if grep -qE '\*\(' /etc/exports 2>/dev/null; then
                echo "[PoC] FAIL: /etc/exports contains wildcard (*) host access."
                INSECURE_EXPORTS=true
            fi
            # Check for no_root_squash
            if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
                echo "[PoC] FAIL: /etc/exports contains no_root_squash."
                INSECURE_EXPORTS=true
            fi
        fi
    fi

    if $INSECURE_EXPORTS; then
        echo "RESULT: Vulnerability still present (insecure NFS exports)."
        exit 1
    fi

    if $NFS_ENABLED; then
        # NFS is enabled but exports appear secure
        echo "[PoC] INFO: NFS is still enabled but exports appear properly restricted."
        echo "[PoC] PASS: NFS exports are secure (no wildcard, no no_root_squash)."
    else
        echo "[PoC] PASS: NFS service is disabled."
    fi

    echo "[PoC] All checks passed - NFS vulnerability remediated (secured)."

    # --- PoC Behavioral Test: Verify NFS exports at runtime ---
    if command -v showmount > /dev/null 2>&1; then
        SHOWMOUNT_OUT=$(showmount -e localhost 2>/dev/null || true)
        if echo "$SHOWMOUNT_OUT" | grep -qE '^\/' ; then
            # Exports exist — check for wildcard
            if echo "$SHOWMOUNT_OUT" | grep -qE '\*|Everyone|0\.0\.0\.0/0'; then
                echo "[PoC] FAIL: showmount shows wildcard export at runtime"
                exit 1
            else
                echo "[PoC] PASS: showmount shows restricted exports at runtime"
            fi
        else
            echo "[PoC] PASS: No NFS exports visible at runtime"
        fi
    elif [ -f /var/lib/nfs/etab ]; then
        # Fallback: check the runtime export table
        if grep -qE '\*\(' /var/lib/nfs/etab 2>/dev/null; then
            echo "[PoC] FAIL: /var/lib/nfs/etab shows wildcard export"
            exit 1
        elif grep -q 'no_root_squash' /var/lib/nfs/etab 2>/dev/null; then
            echo "[PoC] FAIL: /var/lib/nfs/etab contains no_root_squash"
            exit 1
        else
            echo "[PoC] PASS: /var/lib/nfs/etab shows properly restricted exports"
        fi
    else
        echo "[PoC] INFO: Neither showmount nor /var/lib/nfs/etab available for runtime check"
    fi
fi

# --- PoC Behavioral Test: NFS ports must not be live-listening on all interfaces ---
# Even if exports look clean on disk, a running rpc.mountd/nfsd listening on
# 0.0.0.0 is a live exposure. Hybrid: combines ss socket probe + /proc/net
# fallback. Baseline has NFS installed and (on systems where it starts)
# listens on 2049/0.0.0.0 — remediated state either removed nfs-kernel-server
# or disabled it, so no listener.
echo "[PoC] Probing live NFS listener state..."
NFS_LIVE_EXPOSED=false
if command -v ss &>/dev/null; then
    # port 2049 (nfsd) or 111 (rpcbind) bound to wildcard/all interfaces
    if ss -H -lnt '( sport = :2049 or sport = :111 )' 2>/dev/null | \
       grep -qE '(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]):(2049|111)\b'; then
        NFS_LIVE_EXPOSED=true
    fi
elif [ -r /proc/net/tcp ]; then
    # hex 0801 = 2049, 006F = 111; local addr all-zero => wildcard bind
    if awk '{print $2}' /proc/net/tcp 2>/dev/null | \
       grep -qE '^00000000:(0801|006F)$'; then
        NFS_LIVE_EXPOSED=true
    fi
fi

# Also confirm no nfsd kernel threads / rpc.mountd userland proc
if pgrep -x rpc.mountd >/dev/null 2>&1 || pgrep -x rpc.nfsd >/dev/null 2>&1; then
    NFS_LIVE_EXPOSED=true
fi

if $NFS_LIVE_EXPOSED; then
    echo "[PoC] FAIL: NFS/rpcbind is live-listening on wildcard address or daemons running."
    echo "RESULT: Vulnerability still present (live NFS exposure)."
    exit 1
fi
echo "[PoC] PASS: No live NFS/rpcbind listeners or daemons detected."

# ──────────────────────────────────────────────
# Regression Test: Ensure system still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

# Check that filesystem operations work
TESTFILE="/tmp/nfs_regression_test_$$"
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

# If NFS is still installed and configured with proper restrictions,
# verify the NFS config is syntactically valid
if $NFS_INSTALLED && [ -f /etc/exports ]; then
    if command -v exportfs &>/dev/null; then
        if ! exportfs -r 2>/dev/null; then
            echo "[Regression] WARNING: exportfs -r returned non-zero (may be expected in container)."
        else
            echo "[Regression] PASS: NFS exports configuration is valid."
        fi
    fi
fi

echo ""
echo "RESULT: Remediation successful - NFS exposure fixed and system functional."
exit 0
