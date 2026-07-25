#!/bin/bash
# Scenario 27: bob must not have exploitable NOPASSWD sudo. Dynamic check: acting
# AS bob, actually invoke the GTFObin escalation via sudo -n and see whether it
# runs 'id -u' as root (uid 0). We also query the live policy with `sudo -n -l`.
# sudo re-parses the policy on every call, so there is no "not restarted" case.
PASS=true
run_as_bob(){ timeout 8 su - bob -c "$1" 2>/dev/null; }

# awk GTFObin
OUT=$(run_as_bob 'sudo -n /usr/bin/awk "BEGIN{system(\"id -u\")}" 2>/dev/null')
if echo "$OUT" | grep -qx 0; then echo "FAIL [PoC]: bob escalated to root via sudo awk"; PASS=false; fi
# find GTFObin
OUT=$(run_as_bob 'sudo -n /usr/bin/find /etc/hostname -exec id -u ";" 2>/dev/null')
if echo "$OUT" | grep -qx 0; then echo "FAIL [PoC]: bob escalated to root via sudo find"; PASS=false; fi

# live policy must not list dangerous NOPASSWD binaries for bob
if run_as_bob 'sudo -n -l 2>/dev/null' | grep -qiE 'NOPASSWD.*/(awk|tar|nmap|find|vi|less|man)([[:space:]]|$)'; then
    echo "FAIL [PoC]: bob still has a dangerous NOPASSWD sudo rule"; PASS=false
fi

$PASS && echo "PASS [PoC]: bob has no exploitable sudo rules"

# Regression: sudoers must remain syntactically valid.
if visudo -c >/dev/null 2>&1; then echo "PASS [Regression]: sudoers syntax valid"; else echo "FAIL [Regression]: sudoers syntax invalid"; PASS=false; fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
