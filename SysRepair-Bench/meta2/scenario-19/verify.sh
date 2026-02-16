#!/bin/bash
# Verify remediation of PHP-CGI Query String Parameter Injection CVE-2012-1823 (scenario-19)

PASS=0
FAIL=1

##############################################
# PoC Check: /cgi-bin/php?-s must NOT disclose source
##############################################

# Test the primary attack vector: ?-s (source disclosure)
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/cgi-bin/php?-s" 2>/dev/null)

if [ "$RESPONSE" = "200" ]; then
    # Got a 200, check if it returns PHP source code
    BODY=$(curl -s "http://127.0.0.1/cgi-bin/php?-s" 2>/dev/null)
    if echo "$BODY" | grep -qi "<?php\|<code>\|<span"; then
        echo "FAIL: /cgi-bin/php?-s still discloses PHP source code"
        exit $FAIL
    fi
fi

# Test another dangerous vector: ?-d to inject configuration
RESPONSE2=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/cgi-bin/php?-d+allow_url_include%3d1" 2>/dev/null)
if [ "$RESPONSE2" = "200" ]; then
    BODY2=$(curl -s "http://127.0.0.1/cgi-bin/php?-d+allow_url_include%3d1" 2>/dev/null)
    if echo "$BODY2" | grep -qi "<?php\|<code>\|X-Powered-By: PHP"; then
        echo "FAIL: /cgi-bin/php?-d parameter injection still works"
        exit $FAIL
    fi
fi

echo "PASS: PHP-CGI query string parameter injection is blocked"

##############################################
# Regression Check: PHP must still work
##############################################

# Check Apache is running
if ! netstat -tlnp 2>/dev/null | grep -q ':80 '; then
    echo "FAIL: Apache is not listening on port 80"
    exit $FAIL
fi

# Check that a normal PHP page works (via mod_php or properly configured CGI)
PHPTEST=$(curl -s "http://127.0.0.1/info.php" 2>/dev/null)
if ! echo "$PHPTEST" | grep -qi "php\|phpinfo"; then
    # Try alternative test
    PHPTEST2=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/info.php" 2>/dev/null)
    if [ "$PHPTEST2" = "000" ] || [ "$PHPTEST2" = "500" ]; then
        echo "FAIL: PHP is not working (info.php returns error)"
        exit $FAIL
    fi
fi

echo "PASS: PHP and Apache are functional"
exit $PASS
