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
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=6667

# Send a payload and read the full reply. A trailing sleep keeps stdin open so
# netcat does not close the socket before the daemon finishes replying.
irc_send() {  # $1 = payload with \r\n escapes
    { printf "%b" "$1"; sleep 2; } | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

# The IRC daemon must already be running; the verifier must not start it.
if ! pgrep -f ircsim.py >/dev/null 2>&1; then
    echo "FAIL [Regression]: the IRC daemon is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the daemon to answer with the IRC greeting.
UP=0
for i in $(seq 1 20); do
    if echo "$(irc_send 'PING\r\n')" | grep -qi "NOTICE Auth"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: IRC daemon did not answer on port $PORT -- service down/broken." >&2
    exit 1
fi

# PoC: fire the AB; backdoor and look for the command output in the live reply.
BD_MARKER="IRC_BACKDOOR_$$_$(date +%s)"
BD_OUT=$(irc_send "AB;echo ${BD_MARKER}\r\n")
if echo "$BD_OUT" | grep -q "$BD_MARKER"; then
    echo "FAIL [PoC]: the AB; backdoor executed a command (marker '$BD_MARKER' returned)" >&2
    echo "            -- unauthenticated remote code execution on port $PORT." >&2
    exit 1
fi
echo "PASS [PoC]: the AB; backdoor no longer executes commands."

# Regression: the daemon still speaks IRC to a normal client.
REG=$(irc_send "NICK probe\r\nUSER probe 0 * :probe\r\n")
if echo "$REG" | grep -qiE "Welcome to the IRC|running version Unreal|NOTICE Auth"; then
    echo "PASS [Regression]: the IRC daemon still answers a normal registration."
else
    echo "FAIL [Regression]: the IRC daemon did not answer a normal registration -- broken." >&2
    exit 1
fi

echo "All checks passed."
exit 0
