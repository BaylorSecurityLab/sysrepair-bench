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
# PoC checks:        port 6200 yields no command-executing shell; the live FTP
#                    banner no longer advertises the compromised 2.3.4 build
# Regression checks: vsftpd runs, presents an FTP banner, and anonymous FTP still
#                    works on port 21
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: the backdoor PoC is an RCE attempt — a dead
# backdoor listener genuinely cannot execute a command. Collateral damage to the
# LEGITIMATE service (vsftpd) is caught by its own regression checks, which is
# what produces the security-true / regression-false CDR pair when everything is
# killed.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
FTP_PORT=21
BD_PORT=6200

# Regression: the legitimate FTP daemon must already be running; the verifier
# must not start it.
if pgrep -x vsftpd >/dev/null 2>&1; then
    record_reg vsftpd_running 1
else
    record_reg vsftpd_running 0 "vsftpd is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the FTP banner.
UP=0
FTP_BANNER=""
for i in $(seq 1 20); do
    FTP_BANNER=$(printf "QUIT\r\n" | nc -w 5 "$HOST" "$FTP_PORT" 2>/dev/null | head -1 | tr -d '\r') || true
    if echo "$FTP_BANNER" | grep -qE "^220"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg vsftpd_banner 1
else
    record_reg vsftpd_banner 0 "vsftpd did not present an FTP banner on port $FTP_PORT"
fi

# PoC 1: drive the backdoor shell on 6200 and confirm command execution.
BD_MARKER="VSFTPD_BACKDOOR_$$_$(date +%s)"
BD_OUT=$(printf "echo %s; id\n" "$BD_MARKER" | nc -w 5 "$HOST" "$BD_PORT" 2>/dev/null) || true
if echo "$BD_OUT" | grep -q "$BD_MARKER"; then
    record_poc backdoor_shell_closed 0 \
        "the backdoor shell on port $BD_PORT executed a command (marker '$BD_MARKER' returned) -- unauthenticated remote root shell"
else
    record_poc backdoor_shell_closed 1
fi

# PoC 2: the live FTP banner must not still advertise the compromised 2.3.4 build.
if echo "$FTP_BANNER" | grep -q "2\.3\.4"; then
    record_poc banner_not_234 0 \
        "FTP banner still advertises the compromised vsftpd 2.3.4 ($FTP_BANNER)"
else
    record_poc banner_not_234 1
fi

# Regression: anonymous FTP still works on port 21. Deliberately NOT gated on the
# banner probe -- this is a check that must witness a dead daemon.
FTP_OUT=$(printf "USER anonymous\r\nPASS probe@example.com\r\nQUIT\r\n" | nc -w 6 "$HOST" "$FTP_PORT" 2>/dev/null) || true
if echo "$FTP_OUT" | grep -qE "^230"; then
    record_reg anonymous_ftp_login 1
else
    record_reg anonymous_ftp_login 0 \
        "anonymous FTP login no longer works -- FTP broken; last reply: $(echo "$FTP_OUT" | tail -2 | tr -d '\r')"
fi

verify_finish
