#!/bin/bash
# Verification: Scenario 19 - Screen SUID (DC-5)
if stat -c %A /usr/bin/screen 2>/dev/null | grep -q 's'; then
    echo "FAIL [PoC]: /usr/bin/screen still has SUID bit."; exit 1
fi
echo "PASS [PoC]: Screen SUID bit removed."
echo "All checks passed."; exit 0
