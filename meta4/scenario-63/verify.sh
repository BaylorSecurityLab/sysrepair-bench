#!/bin/bash
# Scenario 63: Roundcube 1.6.3 — SVG-Based Stored XSS (CVE-2023-5631)
set -u

###############################################################################
# PoC 1: Apache config or .htaccess must contain Content-Security-Policy
#         header with script-src directive
###############################################################################

APACHE_CONF_DIR="/etc/apache2"
ROUNDCUBE_ROOT="/var/www/html"

CSP_FOUND=0

# Check Apache site configs and conf.d
if grep -rqiE "Content-Security-Policy.*script-src" "$APACHE_CONF_DIR" 2>/dev/null; then
    CSP_FOUND=1
fi

# Check .htaccess in Roundcube root
if [ -f "$ROUNDCUBE_ROOT/.htaccess" ] && \
   grep -qiE "Content-Security-Policy.*script-src" "$ROUNDCUBE_ROOT/.htaccess" 2>/dev/null; then
    CSP_FOUND=1
fi

# Also verify the header is actually served
HTTP_HEADERS=$(curl -sI http://127.0.0.1/ 2>/dev/null || true)
if echo "$HTTP_HEADERS" | grep -qiE "content-security-policy.*script-src"; then
    CSP_FOUND=1
fi

if [ "$CSP_FOUND" -eq 1 ]; then
    echo "PASS [PoC 1]: Content-Security-Policy with script-src is configured."
else
    echo "FAIL [PoC 1]: Content-Security-Policy header with script-src not found." >&2
    exit 1
fi

###############################################################################
# PoC 2: Roundcube config must have SVG-stripping or htmleditor disabled
###############################################################################

RC_CONFIG="$ROUNDCUBE_ROOT/config/config.inc.php"

if [ ! -f "$RC_CONFIG" ]; then
    echo "FAIL [PoC 2]: Roundcube config not found at $RC_CONFIG." >&2
    exit 1
fi

if grep -qE "htmleditor|show_images|allow_svg|blocked_elements" "$RC_CONFIG" 2>/dev/null; then
    echo "PASS [PoC 2]: Roundcube config contains SVG/image stripping settings."
else
    echo "FAIL [PoC 2]: Roundcube config does not set htmleditor or SVG stripping options." >&2
    exit 1
fi

###############################################################################
# Regression: Roundcube web UI on port 80 must respond (200 or 302)
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/ 2>/dev/null || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "PASS [Regression]: Roundcube web UI responding on port 80 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Roundcube web UI not responding on port 80." >&2
exit 1
