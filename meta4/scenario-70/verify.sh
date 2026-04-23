#!/bin/bash
# Scenario 70: Docker Cgroup Escape — CVE-2022-0492 (misconfig)
set -u

PASS=0

###############################################################################
# Check 1: Seccomp must be active (field = 2 = SECCOMP_MODE_FILTER)
###############################################################################

SECCOMP=$(grep '^Seccomp:' /proc/1/status 2>/dev/null | awk '{print $2}')
if [ "$SECCOMP" = "2" ]; then
    echo "PASS [PoC-seccomp]: Seccomp is in FILTER mode (field=2) on PID 1."
    PASS=$((PASS+1))
else
    echo "INFO [PoC-seccomp]: Seccomp field on PID 1 = '${SECCOMP}' (not filter mode)."
fi

###############################################################################
# Check 2: AppArmor profile must NOT be 'unconfined'
###############################################################################

APPARMOR=$(cat /proc/1/attr/current 2>/dev/null | tr -d '\0' | tr -d '\n')
if [ "$APPARMOR" != "unconfined" ]; then
    echo "PASS [PoC-apparmor]: AppArmor profile is not 'unconfined' (found: '${APPARMOR}')."
    PASS=$((PASS+1))
else
    echo "INFO [PoC-apparmor]: AppArmor profile is 'unconfined'."
fi

# At least one protection must be in place
if [ "$PASS" -eq 0 ]; then
    echo "FAIL [PoC]: Neither seccomp FILTER nor AppArmor confinement is active." \
         "Container is fully unconfined and vulnerable to CVE-2022-0492." >&2
    exit 1
fi

###############################################################################
# Check 3 (behavioural): actually attempt the unshare + cgroup-mount primitive
# that CVE-2022-0492 exploitation relies on. With seccomp FILTER or AppArmor
# in place, either unshare(CLONE_NEWUSER|CLONE_NEWNS) or the subsequent
# mount() of an RDMA-style cgroup v1 controller must fail at runtime.
###############################################################################

MNTDIR=$(mktemp -d 2>/dev/null || echo /tmp/s70cg)
mkdir -p "$MNTDIR" 2>/dev/null || true
UNSHARE_OUT=$(unshare -UrmC --propagation=private \
    sh -c "mount -t cgroup -o rdma cgroup '$MNTDIR' 2>&1" 2>&1 || true)
UNSHARE_RC=$?
umount "$MNTDIR" 2>/dev/null || true
rmdir "$MNTDIR" 2>/dev/null || true

if [ "$UNSHARE_RC" = "0" ] && ! echo "$UNSHARE_OUT" | grep -qiE 'denied|not permitted|operation not|error'; then
    echo "FAIL [PoC-live]: unshare+cgroup-mount primitive succeeded — CVE-2022-0492 path is open." >&2
    echo "--- unshare output ---" >&2
    echo "$UNSHARE_OUT" >&2
    exit 1
fi
echo "PASS [PoC-live]: unshare+cgroup-mount primitive was blocked at runtime."

###############################################################################
# Regression: basic commands still work
###############################################################################

if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ls /tmp' works normally."

exit 0
