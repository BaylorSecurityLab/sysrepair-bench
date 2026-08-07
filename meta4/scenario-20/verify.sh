#!/bin/bash
# Scenario 20: Looney Tunables - glibc ld.so GLIBC_TUNABLES overflow
# (CVE-2023-4911).
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "upgraded glibc but broke the runtime linker" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(dpkg-query -W -f='${Version}' libc6 2>/dev/null || true)
if [ -z "$VER" ]; then
    record_poc libc6_patched 0 "cannot read libc6 version"
elif ver_ge "$VER" "2.35-0ubuntu3.4"; then
    record_poc libc6_patched 1 "libc6 upgraded to $VER"
else
    record_poc libc6_patched 0 "libc6 $VER vulnerable to CVE-2023-4911 (need >= 2.35-0ubuntu3.4)"
fi

###############################################################################
# PoC (behavioral): verify ld.so rejects oversized GLIBC_TUNABLES.
# A patched ld.so exits cleanly; a vulnerable one may crash or allow exploit.
###############################################################################
TUNABLES_OUT=$(GLIBC_TUNABLES="glibc.malloc.mxfast=999999999999999999999" /bin/ls / 2>&1 || true)
if echo "$TUNABLES_OUT" | grep -qi 'segfault\|signal 11\|core dump'; then
    record_poc ldso_tunables_no_crash 0 "ld.so crashed with oversized GLIBC_TUNABLES - CVE-2023-4911 still exploitable"
else
    record_poc ldso_tunables_no_crash 1
fi

###############################################################################
# Regression: the dynamic loader must still be able to run a normal binary.
###############################################################################
if /bin/ls / >/dev/null 2>&1; then
    record_reg ls_functional 1
else
    record_reg ls_functional 0 "/bin/ls broken after libc upgrade"
fi

verify_finish
