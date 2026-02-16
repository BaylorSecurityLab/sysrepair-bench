#!/bin/bash
# Verification script for Scenario 29: Distributed Ruby (DRb) Unrestricted RCE
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure DRb is not accessible from all interfaces without ACL
###############################################################################

# Check if DRb is running at all
DRB_RUNNING=0
if pgrep -f 'drb_service' > /dev/null 2>&1; then
    DRB_RUNNING=1
fi

if [ "$DRB_RUNNING" -eq 0 ]; then
    # DRb service is stopped entirely - this is a valid remediation
    echo "PASS [PoC]: DRb service is not running (service disabled)."
else
    # DRb is running - check if it's restricted

    # Check if listening on 0.0.0.0:8787 (unrestricted)
    if netstat -tlnp 2>/dev/null | grep ':8787' | grep -q '0.0.0.0'; then
        # Listening on all interfaces - check if ACL is configured in the script
        DRB_SCRIPT="/opt/drb/drb_service.rb"
        if [ -f "$DRB_SCRIPT" ]; then
            if grep -q 'ACL' "$DRB_SCRIPT" && grep -q 'install_acl\|acl' "$DRB_SCRIPT"; then
                echo "PASS [PoC]: DRb has ACL configured."
            else
                echo "FAIL [PoC]: DRb is listening on 0.0.0.0:8787 without ACL."
                exit 1
            fi
        else
            echo "FAIL [PoC]: DRb is listening on 0.0.0.0:8787 and service script not found for ACL verification."
            exit 1
        fi
    elif netstat -tlnp 2>/dev/null | grep ':8787' | grep -q '127.0.0.1'; then
        # Listening on localhost only - this is a valid remediation
        echo "PASS [PoC]: DRb is bound to 127.0.0.1 only (localhost restricted)."
    else
        # Not listening on 8787 at all while process exists - may be starting up
        echo "PASS [PoC]: DRb is not listening on port 8787 from external interfaces."
    fi

    # Additional check: verify the dangerous methods are removed or service is restricted
    DRB_SCRIPT="/opt/drb/drb_service.rb"
    if [ -f "$DRB_SCRIPT" ]; then
        if grep -q 'exec_command\|system\|`.*cmd' "$DRB_SCRIPT"; then
            # Dangerous methods exist - only acceptable if ACL or localhost binding is in place
            if grep -q 'ACL\|127\.0\.0\.1' "$DRB_SCRIPT"; then
                echo "PASS [PoC]: Dangerous methods exist but access is restricted."
            else
                echo "FAIL [PoC]: DRb script still has dangerous methods without restrictions."
                exit 1
            fi
        fi
    fi
fi

###############################################################################
# Regression Check: If DRb is meant to run locally, verify it works
###############################################################################

if [ "$DRB_RUNNING" -eq 1 ]; then
    # Verify the DRb process is healthy
    if pgrep -f 'drb_service\|ruby.*drb' > /dev/null 2>&1; then
        echo "PASS [Regression]: DRb process is running."
    else
        echo "FAIL [Regression]: DRb process is not running as expected."
        exit 1
    fi

    # Check Ruby is still installed and functional
    if ruby -e 'puts "ok"' 2>/dev/null | grep -q 'ok'; then
        echo "PASS [Regression]: Ruby runtime is functional."
    else
        echo "FAIL [Regression]: Ruby runtime is not working."
        exit 1
    fi
else
    # Service was disabled - just verify system is functional
    echo "PASS [Regression]: DRb service was disabled (valid remediation). System is operational."
fi

echo "All checks passed."
exit 0
