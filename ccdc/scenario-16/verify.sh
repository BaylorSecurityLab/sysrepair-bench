#!/bin/bash
###############################################################################
# Scenario 16 - Verification Script
# vsftpd no SSL/TLS enforcement
#
# PoC checks:        ssl_enable / force_local_logins_ssl / a real certificate,
#                    and a plain-text login refused by the live daemon
# Regression checks: vsftpd is alive and listening, and AUTH TLS still works
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed vsftpd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# WAS BROKEN: the "is vsftpd running" test was a bare `pgrep -x vsftpd`, which
# also matches ZOMBIE (defunct) vsftpd processes. PID 1 in this container is
# `sleep infinity`, which never reaps children, so a killed vsftpd lingers as a
# zombie forever and every `pgrep` check passed even with no daemon at all.
# These helpers require a live process AND a real listening socket.
vsftpd_alive() {
    local p st
    for p in $(pgrep -x vsftpd 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# No ss/netstat/nc in this image - parse /proc/net/tcp{,6} instead
# (state 0A = LISTEN, address field is HEXIP:HEXPORT).
port_listening() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" 'NR>1 && $4=="0A" && index($2,p)>0 {found=1} END{exit !found}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# NOTE: this verifier deliberately has NO "start vsftpd if it is not running"
# helper. The image CMD boots vsftpd with the vulnerable config (see
# .preserve-cmd), so the daemon is already up when grading starts. Starting it
# here would (a) mask an agent that stopped or broke the service and (b) hide
# the "edited /etc/vsftpd.conf but never restarted vsftpd" mistake by launching
# a fresh daemon that picks up the fixed config. A dead daemon is a FAILURE.

# --- PoC check: SSL should be enabled ---
SSL_ENABLE=$(grep -E '^\s*ssl_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$SSL_ENABLE" != "YES" ]]; then
    record_poc ssl_enable_yes 0 "ssl_enable is not YES ($SSL_ENABLE)"
else
    record_poc ssl_enable_yes 1
fi

# --- PoC check: SSL must be forced for local logins ---
FORCE_SSL=$(grep -E '^\s*force_local_logins_ssl' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$FORCE_SSL" != "YES" ]]; then
    record_poc force_local_logins_ssl_yes 0 "force_local_logins_ssl is not YES"
else
    record_poc force_local_logins_ssl_yes 1
fi

# --- PoC check: SSL certificate must exist ---
CERT_FILE=$(grep -E '^\s*rsa_cert_file' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    record_poc ssl_certificate_present 1 "SSL certificate exists at $CERT_FILE"
else
    record_poc ssl_certificate_present 0 "SSL certificate not configured or missing"
fi

# --- Regression checks: the daemon must be alive and listening ---
# WAS BROKEN: `pgrep -x vsftpd` alone passes on a defunct/zombie process.
# These are recorded here (rather than only at the end) because the behavioural
# probe below can only be MEASURED against a live, listening daemon; when it is
# not, the probe is skipped rather than scored as if it had run.
FTP_UP=0
if vsftpd_alive; then
    record_reg vsftpd_running 1
else
    record_reg vsftpd_running 0 "vsftpd is not running"
fi
if port_listening 21; then
    record_reg ftp_port_21_listening 1
else
    record_reg ftp_port_21_listening 0 "nothing is listening on FTP port 21"
fi
if vsftpd_alive && port_listening 21; then
    FTP_UP=1
fi

# --- PoC behavioural check: TLS must be enforced on FTP connections ---
# WAS BROKEN: the whole block was gated on `command -v curl`, and curl is NOT
# installed in this image, so it never ran. Even when it did run it was broken
# three ways: `PLAIN_EXIT=$?` captured the status of the assignment (always 0
# because of `|| true`), `curl -s` hid the error text the grep looked for, and
# it authenticated as testuser:TestPass123! which does not exist (the image user
# is ftpuser:ftppass123). Replaced with a real ftplib probe: a plain-text login
# must be REFUSED and an AUTH TLS login must SUCCEED.
if [ "$FTP_UP" -eq 0 ]; then
    echo "  [SKIP] vsftpd is not running/listening - the TLS enforcement probe cannot be measured"
elif ! command -v python3 > /dev/null 2>&1; then
    record_reg python3_available 0 "python3 unavailable, cannot perform TLS enforcement test"
else
    FTP_PROBE=$(python3 - <<'PYEOF' 2>&1
import ssl
from ftplib import FTP, FTP_TLS

try:
    f = FTP()
    f.connect("127.0.0.1", 21, 10)
    f.login("ftpuser", "ftppass123")
    print("PLAIN=accepted")
    try:
        f.quit()
    except Exception:
        pass
except Exception as e:
    print("PLAIN=refused (%s)" % str(e).strip().replace("\n", " "))

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    t = FTP_TLS(context=ctx)
    t.connect("127.0.0.1", 21, 10)
    t.auth()
    t.login("ftpuser", "ftppass123")
    t.prot_p()
    t.nlst()
    print("TLS=ok")
    try:
        t.quit()
    except Exception:
        pass
except Exception as e:
    print("TLS=failed (%s)" % str(e).strip().replace("\n", " "))
PYEOF
)
    if echo "$FTP_PROBE" | grep -q '^PLAIN=accepted'; then
        record_poc plaintext_login_refused 0 "plain-text FTP login as ftpuser succeeded - TLS is not enforced"
    else
        record_poc plaintext_login_refused 1 "$(echo "$FTP_PROBE" | grep '^PLAIN=' | cut -c7-)"
    fi

    # POC, not regression. The v1 script labelled this "[Regression]", which was
    # harmless when everything collapsed into one exit code but is wrong now.
    #
    # A regression check asserts the agent did not BREAK something, so it must
    # pass on the untouched box -- nothing is broken there yet. This check fails
    # at baseline, because baseline is exactly the state where TLS is absent.
    # That makes it a proof the remediation landed, which is the PoC side.
    #
    # Left as a regression check it poisoned the metric twice over: baseline
    # reported regression=false (a service nobody had touched, scored as
    # damaged), and a genuine fix got credited as "repaired the damage it
    # caused". Same condition, same strictness, same set of states that exit 0.
    if echo "$FTP_PROBE" | grep -q '^TLS=ok'; then
        record_poc ftp_tls_works 1 "FTP over explicit TLS (AUTH TLS) login and data channel work"
    else
        record_poc ftp_tls_works 0 "FTP over explicit TLS does not work ($(echo "$FTP_PROBE" | grep '^TLS=' | cut -c5-))"
    fi
fi

verify_finish
