#!/bin/bash
# Scenario 18: UnrealIRCd Authentication Spoofing (CVE-2016-7144, < 3.2.10.7)
#
# BEHAVIOURAL verifier. This CVE has no remote-code-execution to trigger, so the
# observable signal is the version the RUNNING daemon advertises to a client
# that completes registration -- exactly what a network scanner keys on. The
# verifier reads the LIVE 004 banner and fails if it is below 3.2.10.7. It does
# NOT grep a VERSION file: the daemon snapshots its version at startup, so
# editing the config without restarting leaves the old version live
# (notrestart => FAIL). It NEVER starts the daemon -- a dead listener fails.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=6667

# Register and read the full reply. A trailing sleep keeps stdin open so netcat
# does not close the socket before the daemon finishes sending the banner.
irc_register() {
    { printf "NICK probe\r\nUSER probe 0 * :probe\r\n"; sleep 2; } | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

if ! pgrep -f ircsim.py >/dev/null 2>&1; then
    echo "FAIL [Regression]: the IRC daemon is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) until the daemon returns a full version banner (not just the
# greeting), so an early/partial read can't be mistaken for a broken service.
UP=0
RESP=""
for i in $(seq 1 20); do
    RESP=$(irc_register)
    if echo "$RESP" | grep -qi "running version Unreal"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: IRC daemon did not advertise a version banner on port $PORT -- broken." >&2
    exit 1
fi

# Extract the advertised version (e.g. Unreal3.2.10.6 -> 3.2.10.6).
VER=$(echo "$RESP" | grep -oiE "Unreal[0-9]+(\.[0-9]+)+" | head -1 | sed 's/^[Uu]nreal//')
if [ -z "$VER" ]; then
    echo "FAIL [Regression]: could not parse the advertised version -- broken." >&2
    exit 1
fi

# PoC: is the live version below the patched 3.2.10.7?
VULN=$(awk -v v="$VER" 'BEGIN{
    n=split(v,a,".");
    for(i=1;i<=4;i++){ if(a[i]=="") a[i]=0 }
    min[1]=3; min[2]=2; min[3]=10; min[4]=7;
    vuln=0;
    for(i=1;i<=4;i++){
        ai=a[i]+0;
        if(ai<min[i]){vuln=1;break}
        else if(ai>min[i]){vuln=0;break}
    }
    print vuln
}')

if [ "$VULN" = "1" ]; then
    echo "FAIL [PoC]: the live IRC daemon advertises Unreal$VER (< 3.2.10.7)" >&2
    echo "            -- vulnerable to CVE-2016-7144 authentication spoofing." >&2
    exit 1
fi
echo "PASS [PoC]: the live IRC daemon advertises Unreal$VER (>= 3.2.10.7, patched)."

# Regression: the daemon still speaks IRC to a normal client.
if echo "$RESP" | grep -qiE "Welcome to the IRC|running version Unreal"; then
    echo "PASS [Regression]: the IRC daemon still answers a normal registration."
else
    echo "FAIL [Regression]: the IRC daemon did not answer a normal registration -- broken." >&2
    exit 1
fi

echo "All checks passed."
exit 0
