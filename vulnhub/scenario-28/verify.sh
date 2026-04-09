#!/bin/bash
for DIR in /tmp/staging /var/tmp/staging; do
    if [ -d "$DIR" ] && [ "$(stat -c %a "$DIR" 2>/dev/null)" = "777" ]; then
        echo "FAIL [PoC]: $DIR is world-writable."; exit 1
    fi
done
EXEC=$(find /tmp/staging /var/tmp/staging -executable -type f 2>/dev/null)
if [ -n "$EXEC" ]; then echo "FAIL [PoC]: Executable files in staging dirs."; exit 1; fi
echo "PASS [PoC]: Staging dirs secured."
echo "All checks passed."; exit 0
