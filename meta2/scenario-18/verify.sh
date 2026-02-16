#!/bin/bash
# Verify remediation of UnrealIRCd Authentication Spoofing CVE-2016-7144 (scenario-18)

PASS=0
FAIL=1

##############################################
# PoC Check: IRC version must be >= 3.2.10.7
# or the service must be removed
##############################################

# Check VERSION file if it exists
if [ -f /opt/unrealircd/VERSION ]; then
    VER=$(cat /opt/unrealircd/VERSION 2>/dev/null | tr -d '[:space:]')
    # Parse version components: need >= 3.2.10.7
    MAJOR=$(echo "$VER" | cut -d. -f1)
    MINOR=$(echo "$VER" | cut -d. -f2)
    PATCH=$(echo "$VER" | cut -d. -f3)
    SUB=$(echo "$VER" | cut -d. -f4)

    if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -eq 2 ] && [ "$PATCH" -eq 10 ] 2>/dev/null; then
        if [ -n "$SUB" ] && [ "$SUB" -lt 7 ] 2>/dev/null; then
            echo "FAIL: UnrealIRCd VERSION file shows $VER (vulnerable, need >= 3.2.10.7)"
            exit $FAIL
        fi
    fi
fi

# Check if port 6667 is listening and what version it reports
if netstat -tlnp 2>/dev/null | grep -q ':6667 '; then
    RESPONSE=$(echo -e "NICK testuser\r\nUSER test 0 * :Test\r\n" | nc -w 5 127.0.0.1 6667 2>/dev/null)

    # Check for vulnerable version strings (3.2.10.0 through 3.2.10.6, or older 3.2.x)
    if echo "$RESPONSE" | grep -qiE "Unreal3\.2\.10\.[0-6][^0-9]|Unreal3\.2\.[0-9][^0-9]|Unreal3\.2\.[0-9]$"; then
        echo "FAIL: IRC service reports a vulnerable UnrealIRCd version"
        exit $FAIL
    fi

    echo "PASS: IRC service version is patched or non-vulnerable"
else
    echo "PASS: IRC service on port 6667 has been removed"
fi

##############################################
# Regression Check: If IRC is kept, it must work
##############################################

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
