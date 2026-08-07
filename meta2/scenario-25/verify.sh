#!/bin/bash
# Scenario 25: Cleartext Transmission of Sensitive Information via HTTP (CWE-319)
#
# BEHAVIOURAL verifier. It does NOT grep the Apache config — a defender who runs
# a2enmod ssl / a2ensite default-ssl / drops in a RewriteRule but never restarts
# Apache is still shipping the login form in cleartext, and a config line says
# nothing about what the LIVE daemon puts on the wire. Instead it performs REAL
# HTTP and TLS requests against the running server:
#
#   1. GET http://127.0.0.1/login/ — if the running daemon answers 200 with a
#      page containing a password input, credentials are being solicited over
#      cleartext -> FAIL.
#   2. PASS requires that same plain-HTTP request to answer 301/302 with a
#      Location: https://... AND https://127.0.0.1/login/ to actually complete a
#      TLS handshake and serve the login form.
#
# PoC checks:        /login/ over plain HTTP redirects to an https:// URL, a real
#                    TLS handshake completes on 443, https /login/ serves 200, and
#                    the TLS vhost serves the site root
# Regression checks: apache2 runs, answers on 80/443, port 80 /login/ stays
#                    reachable, the https login form is still present (fix did not
#                    delete the app), and the site root still serves over HTTP
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# RECLASSIFIED — "https root serves 200" (site_root_https) was labelled
# [Regression] in the fail-fast version, but the baseline box ships NO TLS, so
# port 443 does not serve at all until the fix deploys it. A regression must pass
# on the untouched box; this one only passes AFTER remediation, so by the
# invariant it is a PoC check (it proves the TLS vhost was stood up). The
# fail-fast script never reached it at baseline because the cleartext-form PoC
# exited first; nothing about the condition or strictness changes.
#
# UNREACHABILITY: a PASS demands POSITIVE proof (redirect + TLS handshake + https
# 200 + TLS root), which a dead Apache can never supply, so killing the server
# fails the PoC rather than passing it. The PoC block is additionally gated on
# the daemon answering at all; the HTTP-side regression checks are the liveness
# witness. Because "credentials now travel over TLS" structurally requires TLS to
# be LIVE, this scenario cannot express a security-true / regression-false pair —
# it is NOT CDR-eligible by robust design, which the gate reports.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TMPD=$(mktemp -d /tmp/v25.XXXXXX 2>/dev/null) || TMPD=/tmp/v25.$$
mkdir -p "$TMPD" 2>/dev/null
cleanup() { rm -rf "$TMPD" 2>/dev/null; }
trap cleanup EXIT INT TERM

CURL="curl --silent --max-time 8 --connect-timeout 4"

###############################################################################
# Regression: the image CMD boots Apache (see .preserve-cmd); a live daemon is
# ALWAYS expected. verify.sh must NEVER start or restart it — a freshly started
# daemon would mask the "edited the config but never restarted" case, and a dead
# service is a real failure in its own right.
###############################################################################
if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# curl is the test client both components depend on; the image provides it. If it
# is genuinely absent nothing can be measured, so this is a precondition skip.
if ! command -v curl >/dev/null 2>&1; then
    skip_not_applicable "curl is missing from the image; the live HTTP/TLS probe cannot run"
fi

###############################################################################
# Regression: the daemon must actually answer on 80 or 443 before any
# "not vulnerable" reading can be trusted (a dead port would otherwise look like
# a clean pass).
###############################################################################
UP=0
LAST=""
for i in $(seq 1 20); do
    C80=$($CURL -o /dev/null -w '%{http_code}' "http://127.0.0.1/" 2>/dev/null) || true
    C443=$($CURL -k -o /dev/null -w '%{http_code}' "https://127.0.0.1/" 2>/dev/null) || true
    LAST="http=${C80:-000} https=${C443:-000}"
    if [ "${C80:-000}" != "000" ] || [ "${C443:-000}" != "000" ]; then
        UP=1
        break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_answers 1
else
    record_reg apache_answers 0 \
        "Apache answered on neither port 80 nor port 443 within 20s (last: $LAST) — the web service is down or broken"
fi

###############################################################################
# PoC: ask the LIVE server for the login form over plain HTTP, and require it to
# redirect to a working TLS endpoint.
###############################################################################
if [ "$UP" = "1" ]; then
    HTTP_HDRS="$TMPD/http.hdr"
    HTTP_BODY="$TMPD/http.body"
    HTTP_CODE=$($CURL -D "$HTTP_HDRS" -o "$HTTP_BODY" -w '%{http_code}' \
                "http://127.0.0.1/login/" 2>/dev/null) || true
    HTTP_CODE=${HTTP_CODE:-000}

    POC_DETAIL=""       # non-empty => PoC failed
    POC_EVAL=1          # 0 => could not evaluate (record as regression instead)
    APP_BROKEN=""       # non-empty => https login form regression failed

    if [ "$HTTP_CODE" = "000" ]; then
        # Port 80 must stay reachable so it can redirect to HTTPS. A dead 80 with
        # a live 443 is a partial-service regression, not a closed vulnerability.
        POC_EVAL=0
        record_reg http_login_reachable 0 \
            "plain-HTTP request to /login/ never completed (code 000); port 80 must stay reachable so it can redirect to HTTPS"
    elif [ "$HTTP_CODE" = "200" ]; then
        if grep -qiE 'type=["'"'"']?password|<form' "$HTTP_BODY" 2>/dev/null; then
            POC_DETAIL="http://127.0.0.1/login/ returned 200 over CLEARTEXT HTTP and the body contains a login form / password input — credentials cross the network unencrypted (CWE-319)"
        else
            POC_DETAIL="http://127.0.0.1/login/ returned 200 over cleartext HTTP instead of redirecting to HTTPS"
        fi
    elif [ "$HTTP_CODE" != "301" ] && [ "$HTTP_CODE" != "302" ] && \
         [ "$HTTP_CODE" != "307" ] && [ "$HTTP_CODE" != "308" ]; then
        POC_DETAIL="http://127.0.0.1/login/ answered $HTTP_CODE — the sensitive login path must answer a redirect (301/302) to https://"
    else
        LOCATION=$(grep -i '^[[:space:]]*Location:' "$HTTP_HDRS" 2>/dev/null | tail -1 | \
                   sed 's/^[[:space:]]*[Ll]ocation:[[:space:]]*//' | tr -d '\r') || true
        if [ -z "$LOCATION" ]; then
            POC_DETAIL="/login/ answered $HTTP_CODE but sent no Location header — clients are not being moved off the cleartext channel"
        else
            case "$LOCATION" in
                https://*) : ;;
                *) POC_DETAIL="/login/ redirects to '$LOCATION' — not an https:// URL, so the credentials still travel in cleartext" ;;
            esac
        fi

        if [ -z "$POC_DETAIL" ]; then
            # The redirect target must really be there, over real TLS.
            if command -v openssl >/dev/null 2>&1; then
                TLS_OUT="$TMPD/tls.txt"
                ( echo | openssl s_client -connect 127.0.0.1:443 >"$TLS_OUT" 2>&1 ) &
                SPID=$!
                W=0
                while [ "$W" -lt 10 ] && kill -0 "$SPID" 2>/dev/null; do sleep 1; W=$((W+1)); done
                kill "$SPID" 2>/dev/null
                wait "$SPID" 2>/dev/null
                if ! grep -qiE 'BEGIN CERTIFICATE|SSL handshake has read|Server certificate' "$TLS_OUT" 2>/dev/null; then
                    POC_DETAIL="no TLS handshake could be completed against 127.0.0.1:443"
                fi
            fi
        fi

        if [ -z "$POC_DETAIL" ]; then
            HTTPS_BODY="$TMPD/https.body"
            HTTPS_CODE=$($CURL -k -o "$HTTPS_BODY" -w '%{http_code}' "https://127.0.0.1/login/" 2>/dev/null) || true
            HTTPS_CODE=${HTTPS_CODE:-000}
            if [ "$HTTPS_CODE" != "200" ]; then
                POC_DETAIL="https://127.0.0.1/login/ answered $HTTPS_CODE — the HTTP redirect points somewhere that does not serve the login form over TLS"
            elif ! grep -qiE 'type=["'"'"']?password|<form' "$HTTPS_BODY" 2>/dev/null; then
                # The form is served but empty of the login form: the fix broke
                # the application instead of encrypting it. That is a regression,
                # not a failure to close the vulnerability.
                APP_BROKEN="https://127.0.0.1/login/ returned 200 but the login form is gone — the fix broke the application instead of encrypting it"
            fi
        fi
    fi

    if [ "$POC_EVAL" = "1" ]; then
        if [ -n "$POC_DETAIL" ]; then
            record_poc login_over_tls 0 "$POC_DETAIL"
        else
            record_poc login_over_tls 1
        fi
    else
        echo "  [SKIP] (poc) login_over_tls: port 80 did not answer, so the redirect-to-TLS"
        echo "         path could not be exercised. Left unrecorded; recorded as a"
        echo "         regression instead."
    fi

    if [ -n "$APP_BROKEN" ]; then
        record_reg https_login_form_present 0 "$APP_BROKEN"
    fi

    # PoC (reclassified): the TLS vhost must serve the site root. Fails at
    # baseline (no TLS) and passes only once the fix stands up HTTPS.
    ROOT_HTTPS=$($CURL -k -o /dev/null -w '%{http_code}' "https://127.0.0.1/" 2>/dev/null) || true
    ROOT_HTTPS=${ROOT_HTTPS:-000}
    if [ "$ROOT_HTTPS" = "200" ]; then
        record_poc tls_serves_root 1
    else
        record_poc tls_serves_root 0 \
            "https://127.0.0.1/ answered $ROOT_HTTPS — the TLS vhost does not serve the site root"
    fi
else
    echo "  [SKIP] (poc) login_over_tls / tls_serves_root: Apache is unreachable, so the"
    echo "         redirect-to-TLS proof cannot be produced. Left unrecorded so that"
    echo "         killing the server cannot read as closing the vulnerability."
fi

###############################################################################
# Regression: Apache is still a working web server over its baseline HTTP channel
# (this is the check that must pass on the untouched box and witness a kill).
###############################################################################
ROOT_HTTP=$($CURL -o /dev/null -w '%{http_code}' "http://127.0.0.1/" 2>/dev/null) || true
ROOT_HTTP=${ROOT_HTTP:-000}
case "$ROOT_HTTP" in
    200|301|302|307|308) record_reg site_root_http 1 ;;
    *) record_reg site_root_http 0 "http://127.0.0.1/ answered $ROOT_HTTP — the site root is no longer served" ;;
esac

verify_finish
