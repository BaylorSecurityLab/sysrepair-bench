#!/bin/bash
CAPS=$(getcap /usr/bin/python3* /usr/bin/find 2>/dev/null | grep -v '=$')
if [ -n "$CAPS" ]; then
    echo "FAIL [PoC]: Dangerous capabilities found:"; echo "$CAPS"; exit 1
fi
echo "PASS [PoC]: No dangerous capabilities on monitored binaries."
echo "All checks passed."; exit 0
