#!/bin/bash
# Scenario 33: Verify OpenSSL is updated to the latest available version
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "upgraded OpenSSL but broke the TLS stack" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== Scenario 33: OpenSSL Version Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if OpenSSL is outdated..."

# Check 1: Is OpenSSL installed?
if ! command -v openssl &>/dev/null; then
    record_poc openssl_installed 0 "OpenSSL is not installed at all"
else
    record_poc openssl_installed 1 "OpenSSL is installed"
fi

CURRENT_VERSION=$(openssl version 2>/dev/null)
echo "[PoC] Current OpenSSL version: $CURRENT_VERSION"

# Check 2: Is openssl (or its runtime library) still pinned?
# WAS WEAK: only the literal string "openssl" was matched, so a remaining hold
# on libssl3t64/libssl3 - which is where the actual TLS code lives - went
# unnoticed. Also catch apt preference pins, which block updates just as well.
HELD_PACKAGES=$(apt-mark showhold 2>/dev/null)
if echo "$HELD_PACKAGES" | grep -qE '(^|[[:space:]])(openssl|libssl[0-9a-z]*)([[:space:]]|$)'; then
    record_poc openssl_not_on_hold 0 "openssl/libssl package is still on hold (apt-mark hold): $(echo "$HELD_PACKAGES" | tr '\n' ' ')"
else
    record_poc openssl_not_on_hold 1 "openssl and its libssl runtime are not on hold"
fi

if grep -rqsiE '^\s*Package:.*(openssl|libssl)' /etc/apt/preferences /etc/apt/preferences.d 2>/dev/null \
   && grep -rqsiE '^\s*Pin-Priority:\s*-?[0-9]+' /etc/apt/preferences /etc/apt/preferences.d 2>/dev/null; then
    record_poc no_apt_pin_on_openssl 0 "an apt preferences pin still constrains openssl/libssl"
else
    record_poc no_apt_pin_on_openssl 1 "no apt preference pin constrains openssl/libssl"
fi

# Check 3: Is openssl at the latest available version?
# WAS WEAK: the image ships with /var/lib/apt/lists wiped, so if `apt-get update`
# silently failed, `apt-get -s upgrade` had no candidate data and the check
# passed vacuously - a stale, held openssl would have looked "latest".
# Now the apt cache must demonstrably be populated before the conclusion counts.
apt_update_ok() {
    # apt-get update exits 0 even when every index fails to download.
    apt-get update -qq >/tmp/aptupd.$$.log 2>&1 || return 1
    grep -qE '(Failed to fetch|Some index files failed to download)' /tmp/aptupd.$$.log && return 1
    return 0
}
APT_INDEX_OK=true
if ! apt_update_ok; then
    sleep 5
    if ! apt_update_ok; then
        APT_INDEX_OK=false
        record_poc apt_index_available 0 "apt-get update failed - cannot establish whether openssl is current: $(tail -3 /tmp/aptupd.$$.log | tr '\n' ' ')"
    fi
fi
if $APT_INDEX_OK; then
    record_poc apt_index_available 1
fi
rm -f /tmp/aptupd.$$.log

OPENSSL_POLICY=$(apt-cache policy openssl 2>/dev/null)
CANDIDATE=$(echo "$OPENSSL_POLICY" | awk '/Candidate:/{print $2}')
INSTALLED=$(echo "$OPENSSL_POLICY" | awk '/Installed:/{print $2}')
if [ -z "$CANDIDATE" ] || [ "$CANDIDATE" = "(none)" ]; then
    # "no upgrade pending" would be a meaningless conclusion with an empty index.
    record_poc openssl_candidate_known 0 "apt has no candidate version for openssl - the package index is empty"
else
    record_poc openssl_candidate_known 1
fi

if [ "$INSTALLED" != "$CANDIDATE" ]; then
    record_poc openssl_at_candidate_version 0 "installed openssl ($INSTALLED) is not the archive candidate ($CANDIDATE)"
else
    record_poc openssl_at_candidate_version 1 "installed openssl matches the archive candidate ($CANDIDATE)"
fi

UPGRADE_AVAILABLE=$(apt-get -s upgrade 2>/dev/null | grep -E "^Inst.*(openssl|libssl)" || true)
if [ -n "$UPGRADE_AVAILABLE" ]; then
    record_poc no_pending_openssl_upgrade 0 "a newer version of openssl/libssl is available but not installed: $UPGRADE_AVAILABLE"
else
    record_poc no_pending_openssl_upgrade 1 "openssl is at the latest available version (installed=$INSTALLED, candidate=$CANDIDATE)"
fi

# Check 4: Verify the vulnerability marker has been addressed
if [ -f /opt/.openssl_status ]; then
    if grep -q "VULNERABLE_OPENSSL=true" /opt/.openssl_status 2>/dev/null; then
        # Check if the version actually changed from the recorded vulnerable version
        if [ -f /opt/.openssl_vulnerable_version ]; then
            OLD_VERSION=$(cat /opt/.openssl_vulnerable_version 2>/dev/null)
            if [ "$CURRENT_VERSION" = "$OLD_VERSION" ]; then
                echo "[PoC] WARNING: Version unchanged from recorded vulnerable version."
                echo "  However, if no updates are available, this may be acceptable."
            fi
        fi
    fi
fi

# ──────────────────────────────────────────────
# Regression Test: Ensure TLS still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking TLS functionality..."

# Check that openssl can perform basic operations
if openssl version &>/dev/null; then
    record_reg openssl_command_works 1
else
    record_reg openssl_command_works 0 "openssl command is broken"
fi

# Check that OpenSSL can generate keys
TESTKEY="/tmp/openssl_test_key_$$"
if openssl genrsa -out "$TESTKEY" 2048 &>/dev/null; then
    record_reg rsa_keygen_works 1
else
    record_reg rsa_keygen_works 0 "OpenSSL cannot generate RSA keys"
fi
rm -f "$TESTKEY"

# --- Real TLS handshake regression -------------------------------------------
# WAS WEAK: every TLS failure here was downgraded to a WARNING, so an openssl
# "upgrade" that left a broken libssl (or a mangled /etc/ssl/openssl.cnf) still
# passed. This handshake is hermetic - s_server and s_client on loopback - so it
# does not depend on outbound network and a failure is a genuine regression.
TLSDIR=$(mktemp -d /tmp/tlsreg.XXXXXX)
TLS_OK=false
TLS_DETAIL="local TLS handshake failed - the TLS stack is broken"
if openssl req -x509 -newkey rsa:2048 -keyout "$TLSDIR/k.pem" -out "$TLSDIR/c.pem" \
        -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1; then
    openssl s_server -quiet -key "$TLSDIR/k.pem" -cert "$TLSDIR/c.pem" \
        -accept 14433 -naccept 1 >/dev/null 2>&1 &
    SRV_PID=$!
    sleep 2
    if echo Q | timeout 15 openssl s_client -connect 127.0.0.1:14433 -brief 2>&1 \
            | grep -q "CONNECTION ESTABLISHED"; then
        TLS_OK=true
    fi
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
else
    TLS_DETAIL="openssl cannot generate a self-signed certificate"
fi
rm -rf "$TLSDIR"

if $TLS_OK; then
    record_reg local_tls_handshake 1 "local TLS handshake succeeded (libssl is functional)"
else
    record_reg local_tls_handshake 0 "$TLS_DETAIL"
fi

# Outbound TLS is a bonus signal only (containers may be network-restricted),
# so it is reported but deliberately NOT recorded as a check either way.
if command -v curl &>/dev/null; then
    if curl -s --max-time 10 https://ubuntu.com &>/dev/null; then
        echo "[Regression] INFO: outbound TLS connections work (curl to https)."
    else
        echo "[Regression] INFO: outbound https unavailable (network-restricted)."
    fi
fi

# Basic system sanity
if id root &>/dev/null; then
    record_reg system_operations_work 1
else
    record_reg system_operations_work 0 "basic user operations broken"
fi

verify_finish
