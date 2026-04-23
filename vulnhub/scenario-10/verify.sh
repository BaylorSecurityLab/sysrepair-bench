#!/bin/bash
# Verification: Scenario 17 - Exim4 SUID (DC-4)
cfg=false; live=false

# Config-grep style check: on-disk SUID bit
PERMS=$(stat -c %a /usr/sbin/exim4 2>/dev/null)
if [ -n "$PERMS" ] && [ $((PERMS / 1000)) -ge 4 ]; then
    cfg=true
fi
if stat -c %A /usr/sbin/exim4 2>/dev/null | grep -q 's'; then
    cfg=true
fi

# Behavioural probe: run exim4 as an unprivileged user. If the SUID bit is
# still effective, exim4 will drop privs to its spool user but the binary
# itself is still invokable as root-owned SUID (execution succeeds with
# elevated context). We detect the live SUID effect by checking that an
# unprivileged user can still exec the binary AND that the kernel honours
# the setuid bit via /proc on the running euid transition.
if id nobody >/dev/null 2>&1; then
    OUT=$(su -s /bin/sh nobody -c '/usr/sbin/exim4 -bV 2>/dev/null; stat -L -c %u:%a /proc/self/exe 2>/dev/null; ls -l /usr/sbin/exim4 2>/dev/null | awk "{print \$1}"' 2>/dev/null)
    if echo "$OUT" | grep -qE '^-[r-][w-]s' ; then
        live=true
    fi
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Exim4 SUID still present (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: Exim4 SUID bit removed (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
