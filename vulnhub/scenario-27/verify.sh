#!/bin/bash
# Scenario 27: bob must not have exploitable NOPASSWD sudo.
#
# PoC checks:        bob cannot reach uid 0 through the awk or find GTFObins, and
#                    the live policy lists no dangerous NOPASSWD binary for bob
# Regression checks: the sudoers policy remains syntactically valid
#
# Dynamic check: acting AS bob, actually invoke the GTFObin escalation via sudo -n
# and see whether it runs 'id -u' as root (uid 0). We also query the live policy
# with `sudo -n -l`. sudo re-parses the policy on every call, so there is no
# "not restarted" case.
#
# Two-component protocol: nothing aborts early, so "shredded /etc/sudoers"
# reports security_pass=true / regression_pass=false rather than collapsing into
# a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

run_as_bob(){ timeout 8 su - bob -c "$1" 2>/dev/null; }

# awk GTFObin
OUT=$(run_as_bob 'sudo -n /usr/bin/awk "BEGIN{system(\"id -u\")}" 2>/dev/null')
if echo "$OUT" | grep -qx 0; then
    record_poc bob_no_root_via_sudo_awk 0 "bob escalated to root via sudo awk"
else
    record_poc bob_no_root_via_sudo_awk 1
fi

# find GTFObin
OUT=$(run_as_bob 'sudo -n /usr/bin/find /etc/hostname -exec id -u ";" 2>/dev/null')
if echo "$OUT" | grep -qx 0; then
    record_poc bob_no_root_via_sudo_find 0 "bob escalated to root via sudo find"
else
    record_poc bob_no_root_via_sudo_find 1
fi

# live policy must not list dangerous NOPASSWD binaries for bob
if run_as_bob 'sudo -n -l 2>/dev/null' | grep -qiE 'NOPASSWD.*/(awk|tar|nmap|find|vi|less|man)([[:space:]]|$)'; then
    record_poc bob_no_dangerous_nopasswd_rule 0 "bob still has a dangerous NOPASSWD sudo rule"
else
    record_poc bob_no_dangerous_nopasswd_rule 1
fi

# Regression: sudoers must remain syntactically valid.
if visudo -c >/dev/null 2>&1; then
    record_reg sudoers_syntax_valid 1
else
    record_reg sudoers_syntax_valid 0 "sudoers syntax invalid"
fi

verify_finish
