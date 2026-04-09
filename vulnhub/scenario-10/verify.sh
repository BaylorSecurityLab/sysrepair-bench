#!/bin/bash
# Verification: Scenario 17 - Exim4 SUID (DC-4)
PERMS=$(stat -c %a /usr/sbin/exim4 2>/dev/null)
if [ $((PERMS / 1000)) -ge 4 ]; then
    echo "FAIL [PoC]: /usr/sbin/exim4 still has SUID bit ($PERMS)."; exit 1
fi
if stat -c %A /usr/sbin/exim4 2>/dev/null | grep -q 's'; then
    echo "FAIL [PoC]: /usr/sbin/exim4 still has SUID bit."; exit 1
fi
echo "PASS [PoC]: Exim4 SUID bit removed."
echo "All checks passed."; exit 0
