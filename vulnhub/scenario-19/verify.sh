#!/bin/bash
if grep -q 'http_access allow all' /etc/squid/squid.conf 2>/dev/null; then
    echo "FAIL [PoC]: Squid still has 'http_access allow all'."; exit 1
fi
echo "PASS [PoC]: No open 'http_access allow all' in squid.conf."
if pgrep -x squid > /dev/null 2>&1; then echo "PASS [Regression]: Squid running."
else echo "FAIL [Regression]: Squid not running."; exit 1; fi
echo "All checks passed."; exit 0
