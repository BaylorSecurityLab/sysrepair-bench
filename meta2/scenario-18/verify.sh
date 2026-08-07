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
# PoC checks:        the live advertised version is >= 3.2.10.7 (patched)
# Regression checks: the IRC daemon runs, advertises a parseable version banner,
#                    and still handles a normal registration
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the only PoC signal is the version string in the live banner.
# A dead daemon advertises nothing, so a killed listener would leave the version
# unparseable — the PoC is left UNRECORDED unless a full version banner was read,
# and the killed service instead fails the regression checks.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=6667

# Register and read the full reply. A trailing sleep keeps stdin open so netcat
# does not close the socket before the daemon finishes sending the banner.
irc_register() {
    { printf "NICK probe\r\nUSER probe 0 * :probe\r\n"; sleep 2; } | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

# Regression: the daemon must already be running; the verifier must not start it.
if pgrep -f ircsim.py >/dev/null 2>&1; then
    record_reg ircd_running 1
else
    record_reg ircd_running 0 "the IRC daemon is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) until the daemon returns a full version banner (not
# just the greeting), so an early/partial read can't be mistaken for a broken
# service.
UP=0
RESP=""
for i in $(seq 1 20); do
    RESP=$(irc_register) || true
    if echo "$RESP" | grep -qi "running version Unreal"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg ircd_version_banner 1
else
    record_reg ircd_version_banner 0 "IRC daemon did not advertise a version banner on port $PORT -- broken"
fi

# Extract the advertised version (e.g. Unreal3.2.10.6 -> 3.2.10.6).
VER=""
if [ "$UP" = "1" ]; then
    VER=$(echo "$RESP" | grep -oiE "Unreal[0-9]+(\.[0-9]+)+" | head -1 | sed 's/^[Uu]nreal//') || true
fi

# PoC: is the live version below the patched 3.2.10.7?
if [ "$UP" = "1" ] && [ -n "$VER" ]; then
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
        record_poc version_patched 0 \
            "the live IRC daemon advertises Unreal$VER (< 3.2.10.7) -- vulnerable to CVE-2016-7144 authentication spoofing"
    else
        record_poc version_patched 1
    fi
else
    echo "  [SKIP] (poc) version_patched: no live version banner was read, so the"
    echo "         version cannot be judged. Left unrecorded so that killing the"
    echo "         daemon cannot read as patching it."
fi

# Regression: the daemon still speaks IRC to a normal client.
if echo "$RESP" | grep -qiE "Welcome to the IRC|running version Unreal"; then
    record_reg ircd_registration 1
else
    record_reg ircd_registration 0 "the IRC daemon did not answer a normal registration -- broken"
fi

verify_finish
