#!/bin/bash
# Verify remediation of vsftpd 2.3.4 backdoor (scenario-16)

PASS=0
FAIL=1

##############################################
# PoC Check: Port 6200 must NOT be listening
##############################################
if netstat -tlnp 2>/dev/null | grep -q ':6200 '; then
    echo "FAIL: Port 6200 is still listening (backdoor active)"
    exit $FAIL
fi

# Also check if the backdoor script is still present and running
if pgrep -f "backdoor.sh" > /dev/null 2>&1; then
    echo "FAIL: Backdoor script is still running"
    exit $FAIL
fi

# Check the FTP banner does not advertise 2.3.4
BANNER=$(echo -e "QUIT\r\n" | nc -w 3 127.0.0.1 21 2>/dev/null | head -1)
if echo "$BANNER" | grep -qi "2\.3\.4"; then
    echo "FAIL: FTP banner still advertises vsftpd 2.3.4"
    exit $FAIL
fi

echo "PASS: Backdoor on port 6200 is not active and banner is clean"

##############################################
# Regression Check: FTP service must work
##############################################
if ! netstat -tlnp 2>/dev/null | grep -q ':21 '; then
    echo "FAIL: FTP service is not listening on port 21"
    exit $FAIL
fi

# Attempt an anonymous FTP connection
RESPONSE=$(echo -e "USER anonymous\r\nPASS test@test.com\r\nQUIT\r\n" | nc -w 5 127.0.0.1 21 2>/dev/null)
if ! echo "$RESPONSE" | grep -q "230"; then
    echo "FAIL: FTP service is not accepting connections properly"
    exit $FAIL
fi

echo "PASS: FTP service is functional on port 21"
exit $PASS
