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
