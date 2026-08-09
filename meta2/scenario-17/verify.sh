#!/bin/bash
# Scenario 17: UnrealIRCd 3.2.8.1 backdoor -> RCE (CVE-2010-2075)
#
# BEHAVIOURAL verifier. It connects to the RUNNING IRC daemon on 6667 and sends
# the trojan trigger ("AB;<cmd>"); if the command's output comes back, the
# backdoor is live. It does NOT grep ircd.conf or a VERSION file: the daemon
# snapshots its config at startup, so editing the config without restarting the
# process leaves the backdoor active (notrestart => FAIL). It NEVER starts the
# daemon -- a dead listener is a real failure.
#
# PoC checks:        the AB; backdoor no longer executes commands
# Regression checks: the IRC daemon runs, answers a greeting, and still handles a
#                    normal client registration
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: the backdoor PoC is an RCE attempt — a dead
# daemon genuinely cannot execute a command. Collateral damage is caught by the
# regression checks (greeting + normal registration), which fail when the IRC
# service is killed, producing the security-true / regression-false CDR pair.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=6667

# Send a payload and read the full reply. A trailing sleep keeps stdin open so
# netcat does not close the socket before the daemon finishes replying.
irc_send() {  # $1 = payload with \r\n escapes
    { printf "%b" "$1"; sleep 2; } | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

# Regression: the IRC daemon must already be running; the verifier must not start it.
if pgrep -f ircsim.py >/dev/null 2>&1; then
    record_reg ircd_running 1
else
    record_reg ircd_running 0 "the IRC daemon is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the daemon to answer with the IRC greeting.
UP=0
for i in $(seq 1 20); do
    if irc_send 'PING\r\n' | grep -qi "NOTICE Auth"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg ircd_greeting 1
else
    record_reg ircd_greeting 0 "IRC daemon did not answer on port $PORT -- service down/broken"
fi

# PoC: fire the AB; backdoor and look for the command output in the live reply.
BD_MARKER="IRC_BACKDOOR_$$_$(date +%s)"
BD_OUT=$(irc_send "AB;echo ${BD_MARKER}\r\n") || true
if echo "$BD_OUT" | grep -q "$BD_MARKER"; then
    record_poc backdoor_closed 0 \
        "the AB; backdoor executed a command (marker '$BD_MARKER' returned) -- unauthenticated remote code execution on port $PORT"
else
    record_poc backdoor_closed 1
fi

# Regression: the daemon still speaks IRC to a normal client.
REG=$(irc_send "NICK probe\r\nUSER probe 0 * :probe\r\n") || true
if echo "$REG" | grep -qiE "Welcome to the IRC|running version Unreal|NOTICE Auth"; then
    record_reg ircd_registration 1
else
    record_reg ircd_registration 0 "the IRC daemon did not answer a normal registration -- broken"
fi

verify_finish
