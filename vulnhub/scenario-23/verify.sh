#!/bin/bash
if stat -c %A /usr/local/bin/statuscheck 2>/dev/null | grep -q 's'; then
    echo "FAIL [PoC]: statuscheck still has SUID bit."; exit 1
fi
echo "PASS [PoC]: SUID bit removed from statuscheck."
echo "All checks passed."; exit 0
