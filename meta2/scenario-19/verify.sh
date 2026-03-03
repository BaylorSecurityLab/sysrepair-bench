#!/bin/bash
# Verify remediation of PHP-CGI Query String Parameter Injection CVE-2012-1823 (scenario-19)

PASS=0
FAIL=1

##############################################
# PoC Check: CVE-2012-1823 RCE via query string injection
# Attack: POST PHP code to stdin via php://input with -d auto_prepend_file
##############################################

# Use nc (curl/wget not available in this container) for the HTTP POST
# Use double-quoted PHP string to avoid shell quoting issues
PAYLOAD='<?php echo "CVE_2012_1823_PROOF"; ?>'
CONTENT_LENGTH=${#PAYLOAD}
RCE_RESPONSE=$(printf "POST /cgi-bin/php?-d+allow_url_include%%3d1+-d+auto_prepend_file%%3dphp://input HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${CONTENT_LENGTH}\r\n\r\n${PAYLOAD}" \
    | nc -w3 127.0.0.1 80 2>/dev/null)

if echo "$RCE_RESPONSE" | grep -q "CVE_2012_1823_PROOF"; then
    echo "FAIL: CVE-2012-1823 is exploitable — arbitrary PHP code executed via CGI query string injection"
    exit $FAIL
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

# Check that a normal PHP page is reachable via nc
PHP_RESPONSE=$(printf "GET /info.php HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" | nc -w3 127.0.0.1 80 2>/dev/null)
if echo "$PHP_RESPONSE" | grep -qi "php\|phpinfo"; then
    echo "PASS: PHP and Apache are functional"
elif echo "$PHP_RESPONSE" | grep -q "200 OK"; then
    echo "PASS: PHP and Apache are functional"
else
    echo "FAIL: PHP is not working (info.php unreachable or returns error)"
    exit $FAIL
fi

exit $PASS
