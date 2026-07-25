#!/bin/bash
# Scenario 30: dangerous file capabilities must be removed. getcap reads the
# on-disk security.capability xattr - the actual kernel-enforced state, not a
# parsed config claim - so it is ground truth. We fail if find/python3 carry any
# escalation-relevant capability, and additionally try to exploit cap_dac_read_
# search on python by reading /etc/shadow as an unprivileged user.
PASS=true

CAPS=$(getcap /usr/bin/find /usr/bin/python3 /usr/bin/python3.* 2>/dev/null \
    | grep -v '=$' \
    | grep -iE 'cap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace|chown|fowner|net_admin)')
if [ -n "$CAPS" ]; then
    echo "FAIL [PoC]: dangerous capabilities present:"; echo "$CAPS"; PASS=false
else
    echo "PASS [PoC]: no dangerous capabilities on find/python3"
fi

if id nobody >/dev/null 2>&1; then
    for PY in /usr/bin/python3 /usr/bin/python3.9 /usr/bin/python3.7 /usr/bin/python3.8 /usr/bin/python3.10 /usr/bin/python3.11; do
        [ -x "$PY" ] || continue
        if timeout 6 su -s /bin/sh nobody -c "'$PY' -c 'open(\"/etc/shadow\",\"rb\").read(1)'" >/dev/null 2>&1; then
            echo "FAIL [PoC]: $PY can read /etc/shadow as nobody (cap_dac_read_search live)"; PASS=false
        fi
    done
fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
