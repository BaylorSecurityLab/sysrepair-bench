#!/bin/bash
if grep -q 'http_access allow all' /etc/squid/squid.conf 2>/dev/null; then
    echo "FAIL [PoC]: Squid still has 'http_access allow all'."; exit 1
fi
echo "PASS [PoC]: No open 'http_access allow all' in squid.conf."

# Behavioral test: proxy request to external site must be denied
if pgrep -x squid > /dev/null 2>&1; then
    PROXY_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x http://localhost:3128 "http://example.com" 2>/dev/null)
    if [ "$PROXY_CODE" = "200" ]; then
        echo "FAIL [PoC]: Open proxy — external request via Squid returned 200."
        exit 1
    fi
    echo "PASS [PoC]: External proxy request blocked (HTTP $PROXY_CODE)."
fi

if pgrep -x squid > /dev/null 2>&1; then echo "PASS [Regression]: Squid running."
else echo "FAIL [Regression]: Squid not running."; exit 1; fi
echo "All checks passed."; exit 0
