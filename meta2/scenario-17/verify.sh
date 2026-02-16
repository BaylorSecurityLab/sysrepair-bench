#!/bin/bash
# Verify remediation of UnrealIRCd 3.2.8.1 Backdoor (scenario-17)

PASS=0
FAIL=1

##############################################
# PoC Check: IRC must not report version 3.2.8.1
# and AB; backdoor must not execute commands
##############################################

# Check if the vulnerable version file exists
if [ -f /opt/unrealircd/VERSION ]; then
    VER=$(cat /opt/unrealircd/VERSION 2>/dev/null)
    if [ "$VER" = "3.2.8.1" ]; then
        echo "FAIL: UnrealIRCd VERSION file still shows 3.2.8.1"
        exit $FAIL
    fi
fi

# Check if port 6667 is listening
if netstat -tlnp 2>/dev/null | grep -q ':6667 '; then
    # Port is open, check what version it reports
    RESPONSE=$(echo -e "NICK testuser\r\nUSER test 0 * :Test\r\n" | nc -w 5 127.0.0.1 6667 2>/dev/null)
    if echo "$RESPONSE" | grep -qi "Unreal3\.2\.8\.1"; then
        echo "FAIL: IRC service still identifies as UnrealIRCd 3.2.8.1"
        exit $FAIL
    fi

    # Test the AB; backdoor -- it must not execute commands
    BACKDOOR_TEST=$(echo -e "AB;echo BACKDOOR_ACTIVE\r\n" | nc -w 3 127.0.0.1 6667 2>/dev/null)
    if echo "$BACKDOOR_TEST" | grep -q "BACKDOOR_ACTIVE"; then
        echo "FAIL: AB; backdoor is still functional"
        exit $FAIL
    fi

    echo "PASS: IRC service is not vulnerable (version clean, no backdoor)"
else
    echo "PASS: IRC service on port 6667 has been removed"
fi

##############################################
# Regression Check: If IRC is kept, it must work
##############################################

# If port 6667 is listening, verify it responds to basic IRC protocol
if netstat -tlnp 2>/dev/null | grep -q ':6667 '; then
    RESPONSE=$(echo -e "NICK testuser\r\nUSER test 0 * :Test\r\n" | nc -w 5 127.0.0.1 6667 2>/dev/null)
    if [ -z "$RESPONSE" ]; then
        echo "FAIL: IRC service is listening but not responding"
        exit $FAIL
    fi
    echo "PASS: IRC service is functional"
fi

# If IRC was removed entirely, that is an acceptable remediation
exit $PASS
