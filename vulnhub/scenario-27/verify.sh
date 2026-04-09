#!/bin/bash
for CMD in awk tar nmap find vi less man; do
    if grep -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -qi "NOPASSWD.*/$CMD"; then
        echo "FAIL [PoC]: Dangerous sudo entry for $CMD found."; exit 1
    fi
done
echo "PASS [PoC]: No dangerous sudoers entries."
visudo -c > /dev/null 2>&1
if [ $? -eq 0 ]; then echo "PASS [Regression]: sudoers syntax valid."
else echo "FAIL [Regression]: sudoers syntax invalid."; exit 1; fi
echo "All checks passed."; exit 0
