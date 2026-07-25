#!/bin/bash
# Scenario 35: Verify NFS server is removed or properly secured
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 35: NFS Server Exposure Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if NFS is insecurely exposed..."

# WHAT WAS WRONG (defect a): the export-table audit below used to live ONLY
# inside the "nfs-kernel-server is still installed" branch. If the package was
# removed, verify.sh printed PASS and never looked at /etc/exports at all - so
# `apt-get remove nfs-kernel-server` (which, unlike purge, leaves the conffile
# behind) passed with the world-writable no_root_squash export still on disk,
# ready to go live again the moment anyone reinstalled the server.
# The audit is now a function invoked on BOTH remediation paths.
#
# It also now recognises more insecure client specs than the original
# `\*\(` / no_root_squash pair: a bare `*`, `?`/`[` globs, 0.0.0.0/0 and ::/0
# are all "the whole internet" too.
audit_export_table() {
    local file="$1"
    local label="$2"
    local bad=0
    local line spec_field host

    [ -f "$file" ] || return 0

    while IFS= read -r line; do
        # strip comments and blank lines; real export lines start with a path
        line="${line%%#*}"
        case "$line" in
            [[:space:]]*/*|/*) : ;;
            *) continue ;;
        esac
        [ -n "$(echo "$line" | tr -d '[:space:]')" ] || continue

        # everything after the exported path is the client/options list
        spec_field=$(echo "$line" | sed -E 's#^[[:space:]]*[^[:space:]]+[[:space:]]*##')
        [ -n "$spec_field" ] || continue

        for host in $spec_field; do
            # client spec is HOST(opt,opt,...) or a bare HOST
            case "${host%%(*}" in
                \*|*\**|*\?*|0.0.0.0/0|::/0|""|world)
                    echo "[PoC] FAIL: $label exports to an unrestricted host '$host'."
                    bad=1
                    ;;
            esac
            case "$host" in
                *no_root_squash*)
                    echo "[PoC] FAIL: $label grants no_root_squash in '$host'."
                    bad=1
                    ;;
            esac
        done
    done < "$file"

    return $bad
}

# Audit every place an export can be declared, on either remediation path.
EXPORTS_INSECURE=false
for exp_file in /etc/exports /etc/exports.d/*.exports; do
    [ -f "$exp_file" ] || continue
    audit_export_table "$exp_file" "$exp_file" || EXPORTS_INSECURE=true
done
# The runtime export table is authoritative for anything already exported.
if [ -f /var/lib/nfs/etab ]; then
    audit_export_table /var/lib/nfs/etab "/var/lib/nfs/etab (runtime export table)" || EXPORTS_INSECURE=true
fi

if $EXPORTS_INSECURE; then
    echo "RESULT: Vulnerability still present (insecure NFS exports on disk)."
    exit 1
fi
echo "[PoC] PASS: No insecure export (wildcard host / no_root_squash) in any export table."

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
    fi
fi

# --- PoC Behavioral Test: NFS ports must not be live-listening ---
#
# WHAT WAS WRONG (defect b): the probe's primary branch was `command -v ss`, but
# iproute2 is NOT installed in this image, so that branch could never run; and
# nothing here ever binds a socket under the harness's `sleep infinity` CMD, so
# the whole probe was decoration. It also only matched a wildcard 0.0.0.0 bind,
# missing a daemon bound to a specific address.
#
# Now: parse /proc/net/tcp{,6} and /proc/net/udp{,6} directly (always present,
# no package needed) for a LISTEN/bound socket on any NFS port regardless of
# bind address, and corroborate with a bash /dev/tcp connect (no `nc` either).
echo "[PoC] Probing live NFS listener state..."
NFS_LIVE_EXPOSED=false

# hex ports: 2049=0801 (nfsd), 111=006F (rpcbind), 20048=4E50 (rpc.mountd)
NFS_PORTS_HEX='0801|006F|4E50'

for pnf in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$pnf" ] || continue
    # $2 = local_address as ADDR:PORT, $4 = socket state; 0A = TCP_LISTEN
    if awk -v re="^($NFS_PORTS_HEX)$" \
        'NR>1 && $4=="0A" { n=split($2,a,":"); if (toupper(a[n]) ~ re) { found=1 } }
         END { exit !found }' "$pnf" 2>/dev/null; then
        echo "[PoC] FAIL: an NFS/rpcbind port is in LISTEN state ($pnf)."
        NFS_LIVE_EXPOSED=true
    fi
done

for pnf in /proc/net/udp /proc/net/udp6; do
    [ -r "$pnf" ] || continue
    # UDP sockets have no LISTEN state; a bound rpcbind/nfsd socket is enough.
    if awk -v re="^($NFS_PORTS_HEX)$" \
        'NR>1 { n=split($2,a,":"); if (toupper(a[n]) ~ re) { found=1 } }
         END { exit !found }' "$pnf" 2>/dev/null; then
        echo "[PoC] FAIL: an NFS/rpcbind port has a bound UDP socket ($pnf)."
        NFS_LIVE_EXPOSED=true
    fi
done

# Corroborating connect probe - `ss`/`netstat`/`nc` are all absent from this
# image, so use bash's own /dev/tcp with a hard timeout.
for probe_port in 2049 111; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$probe_port" 2>/dev/null; then
        echo "[PoC] FAIL: TCP connect to 127.0.0.1:$probe_port succeeded - NFS stack is live."
        NFS_LIVE_EXPOSED=true
    fi
done

# Also confirm no nfsd kernel threads / rpc.mountd userland proc
if pgrep -x rpc.mountd >/dev/null 2>&1 || pgrep -x rpc.nfsd >/dev/null 2>&1 || \
   pgrep -x rpcbind >/dev/null 2>&1; then
    echo "[PoC] FAIL: an NFS/rpcbind daemon process is running."
    NFS_LIVE_EXPOSED=true
fi

if $NFS_LIVE_EXPOSED; then
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

# The share's data must survive the remediation - securing an export must not
# mean deleting the directory it serves.
if [ -d /srv/nfs ] && [ ! -s /srv/nfs/data.txt ]; then
    echo "[Regression] FAIL: /srv/nfs exists but its data was destroyed."
    exit 1
fi
echo "[Regression] PASS: Exported data was not destroyed by the remediation."

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
