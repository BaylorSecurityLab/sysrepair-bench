#!/bin/bash
if grep -q '0.0.0.0.*8888' /usr/local/bin/custom-service.sh 2>/dev/null; then
    echo "FAIL [PoC]: Service still bound to 0.0.0.0."; exit 1
fi
echo "PASS [PoC]: Service not on all interfaces."
echo "All checks passed."; exit 0
