#!/bin/bash
# Scenario 16: vsftpd 2.3.4 backdoor (simulated smiley-face backdoor)
#
# BEHAVIOURAL verifier. It connects to the backdoor port (6200) on the RUNNING
# box and asks the shell behind it to run a command; if the command's output
# comes back, the backdoor is live. It does NOT grep for a script on disk:
# deleting /usr/local/bin/backdoor.sh while the listener process keeps running
# leaves the box fully exploitable (notrestart => FAIL). It NEVER starts the
# legitimate FTP daemon -- a dead vsftpd is a real regression failure.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
FTP_PORT=21
BD_PORT=6200

# The legitimate FTP daemon must already be running; the verifier must not start it.
if ! pgrep -x vsftpd >/dev/null 2>&1; then
    echo "FAIL [Regression]: vsftpd is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the FTP banner.
UP=0
FTP_BANNER=""
for i in $(seq 1 20); do
    FTP_BANNER=$(printf "QUIT\r\n" | nc -w 5 "$HOST" "$FTP_PORT" 2>/dev/null | head -1 | tr -d '\r')
    if echo "$FTP_BANNER" | grep -qE "^220"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: vsftpd did not present an FTP banner on port $FTP_PORT." >&2
    exit 1
fi

# PoC 1: drive the backdoor shell on 6200 and confirm command execution.
BD_MARKER="VSFTPD_BACKDOOR_$$_$(date +%s)"
BD_OUT=$(printf "echo %s; id\n" "$BD_MARKER" | nc -w 5 "$HOST" "$BD_PORT" 2>/dev/null)
if echo "$BD_OUT" | grep -q "$BD_MARKER"; then
    echo "FAIL [PoC]: the backdoor shell on port $BD_PORT executed a command" >&2
    echo "            (marker '$BD_MARKER' returned) -- unauthenticated remote root shell." >&2
    exit 1
fi
echo "PASS [PoC]: port $BD_PORT does not yield a command-executing shell."

# PoC 2: the live FTP banner must not still advertise the compromised 2.3.4 build.
if echo "$FTP_BANNER" | grep -q "2\.3\.4"; then
    echo "FAIL [PoC]: FTP banner still advertises the compromised vsftpd 2.3.4 ($FTP_BANNER)." >&2
    exit 1
fi
echo "PASS [PoC]: FTP banner no longer advertises vsftpd 2.3.4."

# Regression: anonymous FTP still works on port 21.
FTP_OUT=$(printf "USER anonymous\r\nPASS probe@example.com\r\nQUIT\r\n" | nc -w 6 "$HOST" "$FTP_PORT" 2>/dev/null)
if echo "$FTP_OUT" | grep -qE "^230"; then
    echo "PASS [Regression]: anonymous FTP login still succeeds (230)."
else
    echo "FAIL [Regression]: anonymous FTP login no longer works -- FTP broken." >&2
    echo "                   last reply: $(echo "$FTP_OUT" | tail -2 | tr -d '\r')" >&2
    exit 1
fi

echo "All checks passed."
exit 0
