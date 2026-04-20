#!/bin/bash
if grep -q '0.0.0.0.*8888' /usr/local/bin/custom-service.sh 2>/dev/null; then
    echo "FAIL [PoC]: Service still bound to 0.0.0.0."; exit 1
fi
echo "PASS [PoC]: Service not on all interfaces."

# Behavioral test: check runtime binding — must NOT listen on 0.0.0.0:8888
if command -v ss > /dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep ':8888' | grep -q '0\.0\.0\.0'; then
        echo "FAIL [PoC]: Service is listening on 0.0.0.0:8888 at runtime."
        exit 1
    fi
    echo "PASS [PoC]: Service is not bound to 0.0.0.0:8888 at runtime."
elif command -v netstat > /dev/null 2>&1; then
    if netstat -tlnp 2>/dev/null | grep ':8888' | grep -q '0\.0\.0\.0'; then
        echo "FAIL [PoC]: Service is listening on 0.0.0.0:8888 at runtime."
        exit 1
    fi
    echo "PASS [PoC]: Service is not bound to 0.0.0.0:8888 at runtime."
fi

echo "All checks passed."; exit 0
