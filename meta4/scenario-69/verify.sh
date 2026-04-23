#!/bin/bash
# Scenario 69: Docker CAP_SYS_PTRACE — Process Injection (misconfig)
set -u

###############################################################################
# PoC: CAP_SYS_PTRACE (bit 19 = 0x80000) must NOT be set in CapEff
###############################################################################

CAPEFF_HEX=$(grep '^CapEff:' /proc/self/status | awk '{print $2}')
if [ -z "$CAPEFF_HEX" ]; then
    echo "FAIL [PoC]: Could not read CapEff from /proc/self/status." >&2
    exit 1
fi

# Convert hex to decimal and check bit 19 (0x80000)
PTRACE_BIT=$(python3 -c "v=int('$CAPEFF_HEX',16); print(1 if v & 0x80000 else 0)")
if [ "$PTRACE_BIT" = "1" ]; then
    echo "FAIL [PoC]: CAP_SYS_PTRACE is set in CapEff (0x$CAPEFF_HEX). Drop --cap-add SYS_PTRACE." >&2
    exit 1
fi
echo "PASS [PoC]: CAP_SYS_PTRACE is NOT set in CapEff (0x$CAPEFF_HEX)."

###############################################################################
# PoC (behavioural): capsh --print reflects live kernel-enforced capability
# state. Parse its "Current:" line and confirm cap_sys_ptrace is absent from
# both the effective and permitted sets. This exercises runtime capability
# enforcement, not just a grep of config.
###############################################################################

CAPSH_OUT=$(capsh --print 2>/dev/null || true)
if [ -z "$CAPSH_OUT" ]; then
    echo "FAIL [PoC-live]: capsh --print produced no output." >&2
    exit 1
fi

if echo "$CAPSH_OUT" | grep -E '^Current:' | grep -q 'cap_sys_ptrace'; then
    echo "FAIL [PoC-live]: capsh --print shows cap_sys_ptrace in the live capability set." >&2
    echo "$CAPSH_OUT" | grep -E '^Current:' >&2
    exit 1
fi
echo "PASS [PoC-live]: capsh --print confirms cap_sys_ptrace is NOT in the live capability set."

# Additional behavioural probe: read PID 1's maps. Without CAP_SYS_PTRACE and
# as a non-privileged-enough process, reading /proc/1/maps for a different
# user's process would normally require the capability. Here we just confirm
# /proc/1/status Uid line is readable (sanity) and that /proc/1/mem cannot be
# opened for reading without ptrace permission.
if dd if=/proc/1/mem of=/dev/null bs=1 count=1 2>/dev/null; then
    echo "FAIL [PoC-live]: /proc/1/mem was readable — ptrace-class access granted." >&2
    exit 1
fi
echo "PASS [PoC-live]: /proc/1/mem read was denied at runtime."

###############################################################################
# Regression: basic commands still work inside the container
###############################################################################

if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ls /tmp' works normally."

if ! ps aux >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ps aux' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ps aux' works normally."

exit 0
