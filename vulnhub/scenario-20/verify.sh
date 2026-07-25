#!/bin/bash
# Scenario 20: Apache CGI Shellshock (CVE-2014-6271).
#
# The image ships bash 4.3.0 (built from source, pre-patch-25), so Shellshock is
# genuinely present. dpkg still records Debian's patched bash, so the fix is to
# reinstall/upgrade bash (apt-get install --reinstall bash) - which restores the
# patched /bin/bash - and no service restart is needed because mod_cgi forks a
# fresh bash per request.
#
# Two dynamic checks: the direct function-export parser probe, and the REAL
# attack surface - a crafted User-Agent through the live Apache CGI over HTTP.
PASS=true

# --- PoC 1: direct CVE-2014-6271 function-export probe ---
RESULT=$(env x='() { :;}; echo SHELLSHOCK' /bin/bash -c "echo safe" 2>/dev/null)
if echo "$RESULT" | grep -q "SHELLSHOCK"; then
    echo "FAIL [PoC]: /bin/bash still parses the exported-function payload (CVE-2014-6271)."
    PASS=false
else
    echo "PASS [PoC]: /bin/bash rejects the Shellshock payload."
fi

# --- PoC 2: exploit it the way an attacker would, over the live CGI ---
# mod_cgi copies request headers into the environment, so a malicious
# User-Agent reaches the CGI's bash. curl is not in the image; use /dev/tcp.
# Apache must be running for this to mean anything; a dead server is a FAIL,
# not a skip.
if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running (the CGI attack surface is down)."
    PASS=false
else
    MARK="SHELLSHOCK_$$_$(awk 'BEGIN{srand();print int(rand()*1e6)}')"
    RESP=$(MARK="$MARK" timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 7
        printf "GET /cgi-bin/test.cgi HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: () { :;}; echo; echo %s\r\nConnection: close\r\n\r\n" "$MARK" >&3
        cat <&3
    ' 2>/dev/null)

    if [ -z "$RESP" ]; then
        echo "FAIL [Regression]: no HTTP response from the CGI endpoint."
        PASS=false
    elif echo "$RESP" | grep -q "$MARK"; then
        echo "FAIL [PoC]: the CGI executed an injected command via a crafted User-Agent (Shellshock over HTTP)."
        PASS=false
    else
        echo "PASS [PoC]: the CGI did not execute the injected command."
        # Regression: the CGI must still serve its legitimate output.
        if echo "$RESP" | grep -q "CGI Test:"; then
            echo "PASS [Regression]: the CGI still returns its normal output."
        else
            echo "FAIL [Regression]: the CGI no longer returns its expected output."
            PASS=false
        fi
    fi
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
