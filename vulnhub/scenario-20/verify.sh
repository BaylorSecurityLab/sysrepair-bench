#!/bin/bash
# Scenario 20: Apache CGI Shellshock (CVE-2014-6271).
#
# PoC checks:        /bin/bash refuses the exported-function payload, and a
#                    crafted User-Agent through the live CGI does not execute
# Regression checks: apache2 is running, the CGI endpoint answers HTTP, and the
#                    CGI still returns its normal output
#
# The image ships bash 4.3.0 (built from source, pre-patch-25), so Shellshock is
# genuinely present. dpkg still records Debian's patched bash, so the fix is to
# reinstall/upgrade bash (apt-get install --reinstall bash) - which restores the
# patched /bin/bash - and no service restart is needed because mod_cgi forks a
# fresh bash per request.
#
# Two dynamic checks: the direct function-export parser probe, and the REAL
# attack surface - a crafted User-Agent through the live Apache CGI over HTTP.
#
# Two-component protocol: nothing aborts early, so "patched bash but killed
# apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC 1: direct CVE-2014-6271 function-export probe ---
RESULT=$(env x='() { :;}; echo SHELLSHOCK' /bin/bash -c "echo safe" 2>/dev/null)
if echo "$RESULT" | grep -q "SHELLSHOCK"; then
    record_poc bash_rejects_function_export 0 "/bin/bash still parses the exported-function payload (CVE-2014-6271)"
else
    record_poc bash_rejects_function_export 1
fi

# --- Regression: apache must be running (the CGI attack surface) ---
if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (the CGI attack surface is down)"
fi

# --- PoC 2: exploit it the way an attacker would, over the live CGI ---
# mod_cgi copies request headers into the environment, so a malicious
# User-Agent reaches the CGI's bash. curl is not in the image; use /dev/tcp.
MARK="SHELLSHOCK_$$_$(awk 'BEGIN{srand();print int(rand()*1e6)}')"
RESP=$(MARK="$MARK" timeout 10 bash -c '
    exec 3<>/dev/tcp/127.0.0.1/80 || exit 7
    printf "GET /cgi-bin/test.cgi HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: () { :;}; echo; echo %s\r\nConnection: close\r\n\r\n" "$MARK" >&3
    cat <&3
' 2>/dev/null)

if [ -z "$RESP" ]; then
    record_reg cgi_http_response 0 "no HTTP response from the CGI endpoint"
else
    record_reg cgi_http_response 1
fi

if echo "$RESP" | grep -q "$MARK"; then
    record_poc cgi_shellshock_blocked 0 "the CGI executed an injected command via a crafted User-Agent (Shellshock over HTTP)"
else
    record_poc cgi_shellshock_blocked 1
    # Regression: the CGI must still serve its legitimate output. Evaluated only
    # on the non-exploited path, exactly as the pre-migration script did.
    if [ -n "$RESP" ]; then
        if echo "$RESP" | grep -q "CGI Test:"; then
            record_reg cgi_normal_output 1
        else
            record_reg cgi_normal_output 0 "the CGI no longer returns its expected output"
        fi
    fi
fi

verify_finish
