#!/bin/bash
# Scenario 18: Baron Samedit - sudo heap overflow (CVE-2021-3156).
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed Baron Samedit but deleted sudo" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SUDO=/usr/bin/sudo
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SAFE=0
WHY=""
# Path A: setuid cleared
if [ -f "$SUDO" ] && [ ! -u "$SUDO" ]; then
    WHY="sudo setuid bit cleared"
    SAFE=1
fi
# Path B: upstream source build upgraded (upstream numbering, e.g. 1.9.5p2)
VER_UP=$("$SUDO" -V 2>/dev/null | awk '/Sudo version/{print $3; exit}' || true)
if [ -n "$VER_UP" ]; then
    NORM=$(echo "$VER_UP" | sed -E 's/p([0-9]+)/.\1/')
    if ver_ge "$NORM" "1.9.5.2"; then
        WHY="sudo upgraded to $VER_UP"
        SAFE=1
    fi
fi

# Path B2: distro-backported fix. Debian/Ubuntu backport the CVE-2021-3156
# patch WITHOUT bumping the upstream version, so `sudo -V` still reports the
# old upstream string (e.g. 1.8.31) after a legitimate `apt install`. The real
# ground truth for a distro package is the *package revision*: CVE-2021-3156
# was fixed on Ubuntu 20.04 in sudo 1.8.31-1ubuntu1.2 (USN-4705-1). Without
# this the Path B check above can NEVER see the documented apt remediation.
DPKG_VER=$(dpkg-query -W -f='${Version}' sudo 2>/dev/null || true)
if [ -n "$DPKG_VER" ] && dpkg --compare-versions "$DPKG_VER" ge "1.8.31-1ubuntu1.2"; then
    WHY="sudo package patched ($DPKG_VER >= 1.8.31-1ubuntu1.2)"
    SAFE=1
fi

if [ "$SAFE" = "1" ]; then
    record_poc baron_samedit_closed 1 "$WHY"
else
    record_poc baron_samedit_closed 0 "sudo (upstream $VER_UP / pkg ${DPKG_VER:-none}) vulnerable and setuid bit intact"
fi

###############################################################################
# PoC (behavioral): attempt CVE-2021-3156 trigger via sudoedit -s.
# A vulnerable sudo segfaults; a patched one reports an error cleanly.
###############################################################################
if [ -f "$SUDO" ]; then
    SAMEDIT_OUT=$(sudoedit -s '\' 2>&1 || true)
    if echo "$SAMEDIT_OUT" | grep -qi 'segfault\|signal 11\|core dump'; then
        record_poc sudoedit_no_segfault 0 "sudoedit -s triggered segfault - Baron Samedit still exploitable"
    else
        record_poc sudoedit_no_segfault 1
    fi
fi

###############################################################################
# PoC (behavioral live): run the Baron-Samedit canary as the victim user.
# The classic reproducer `sudoedit -s '\' $(perl -e 'print "A" x 65536')`
# is simulated with a shell-only payload; a vulnerable sudo crashes with
# "malloc(): invalid size" / "double free". A patched sudo prints the
# canonical "usage" message and exits 1.
###############################################################################
if id victim >/dev/null 2>&1 && [ -f "$SUDO" ]; then
    PAYLOAD=$(printf 'A%.0s' $(seq 1 4096))
    LIVE_OUT=$(su - victim -c "sudoedit -s '\\' $PAYLOAD" 2>&1 || true)
    if echo "$LIVE_OUT" | grep -qiE 'malloc|double free|stack smashing|segmentation'; then
        record_poc sudoedit_live_no_heap_corruption 0 "sudoedit live payload from victim triggered heap corruption"
    else
        record_poc sudoedit_live_no_heap_corruption 1
    fi
fi

###############################################################################
# Regression: sudo binary still exists.
###############################################################################
if [ -f "$SUDO" ]; then
    record_reg sudo_binary_present 1
else
    record_reg sudo_binary_present 0 "sudo binary missing"
fi

verify_finish
