#!/bin/bash
# Scenario 16: vsftpd no SSL/TLS enforcement
# Verification: PoC should fail (SSL enabled) AND functionality test should pass

PASS=true

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

# --- PoC Test: SSL should be enabled ---
SSL_ENABLE=$(grep -E '^\s*ssl_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$SSL_ENABLE" != "YES" ]]; then
    echo "FAIL [PoC]: ssl_enable is not YES ($SSL_ENABLE)"
    PASS=false
else
    echo "PASS [PoC]: ssl_enable is YES"
fi

# Check that SSL is forced for local logins
FORCE_SSL=$(grep -E '^\s*force_local_logins_ssl' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$FORCE_SSL" != "YES" ]]; then
    echo "FAIL [PoC]: force_local_logins_ssl is not YES"
    PASS=false
else
    echo "PASS [PoC]: force_local_logins_ssl is YES"
fi

# Check SSL certificate exists
CERT_FILE=$(grep -E '^\s*rsa_cert_file' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    echo "PASS [PoC]: SSL certificate exists at $CERT_FILE"
else
    echo "FAIL [PoC]: SSL certificate not configured or missing"
    PASS=false
fi

# --- PoC Behavioral Test: Verify TLS is enforced on FTP connections ---
# WAS BROKEN: the whole block was gated on `command -v curl`, and curl is NOT
# installed in this image, so it never ran. Even when it did run it was broken
# three ways: `PLAIN_EXIT=$?` captured the status of the assignment (always 0
# because of `|| true`), `curl -s` hid the error text the grep looked for, and
# it authenticated as testuser:TestPass123! which does not exist (the image user
# is ftpuser:ftppass123). Replaced with a real ftplib probe: a plain-text login
# must be REFUSED and an AUTH TLS login must SUCCEED.
if ! vsftpd_alive; then
    echo "FAIL [PoC]: vsftpd is not running, cannot perform TLS enforcement test"
    PASS=false
elif ! port_listening 21; then
    echo "FAIL [PoC]: nothing is listening on FTP port 21, cannot perform TLS enforcement test"
    PASS=false
elif ! command -v python3 > /dev/null 2>&1; then
    echo "FAIL [PoC]: python3 unavailable, cannot perform TLS enforcement test"
    PASS=false
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
        echo "FAIL [PoC]: plain-text FTP login as ftpuser succeeded - TLS is not enforced"
        PASS=false
    else
        echo "PASS [PoC]: plain-text FTP login rejected ($(echo "$FTP_PROBE" | grep '^PLAIN=' | cut -c7-))"
    fi

    if echo "$FTP_PROBE" | grep -q '^TLS=ok'; then
        echo "PASS [Regression]: FTP over explicit TLS (AUTH TLS) login and data channel work"
    else
        echo "FAIL [Regression]: FTP over explicit TLS does not work ($(echo "$FTP_PROBE" | grep '^TLS=' | cut -c5-))"
        PASS=false
    fi
fi

# --- Regression Test: vsftpd should be running ---
# WAS BROKEN: `pgrep -x vsftpd` alone passes on a defunct/zombie process.
if vsftpd_alive && port_listening 21; then
    echo "PASS [Regression]: vsftpd is running and listening on port 21"
else
    echo "FAIL [Regression]: vsftpd is not running/listening on port 21"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
