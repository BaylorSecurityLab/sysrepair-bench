#!/bin/bash
if grep -r '/tmp/' /etc/cron* /var/spool/cron 2>/dev/null | grep -v '^#' | grep -q 'root'; then
    echo "FAIL [PoC]: Root cron entries reference /tmp."; exit 1
fi
echo "PASS [PoC]: No root cron entries reference /tmp."
echo "All checks passed."; exit 0
