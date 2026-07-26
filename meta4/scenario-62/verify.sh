#!/bin/bash
# Scenario 62: Dovecot 2.3.x — Pre-Auth Buffer Overflow (CVE-2019-11500)
# Unpatchable in place; compensating controls required:
#   * LIVE network restriction of 143/993 (iptables, read from kernel table)
#   * require TLS (ssl = required) and login_trusted_networks (doveconf parse)
# The verifier never starts dovecot — a dead daemon is a FAIL.
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (needed to read the firewall)." >&2
    exit 1
fi

# Live DROP/REJECT rule for a given dport in the running INPUT chain?
firewalled() {
    iptables -S INPUT 2>/dev/null | grep -E -- '--dport[= ]'"$1"'([^0-9]|$)' | grep -qE -- '-j (DROP|REJECT)'
}

###############################################################################
# PoC 1: both IMAP (143) and IMAPS (993) must be firewalled from untrusted
# sources (LIVE kernel table) to shrink the pre-auth attack surface.
###############################################################################
if ! firewalled 143 || ! firewalled 993; then
    echo "FAIL [PoC 1]: IMAP 143 and/or IMAPS 993 lack a live iptables DROP/REJECT rule." >&2
    exit 1
fi
echo "PASS [PoC 1]: iptables restricts both 143 and 993 (live rules)."

###############################################################################
# PoC 2: TLS must be REQUIRED. Dovecot's real directive is `ssl = required`;
# doveconf reports the effective, parsed value (and fails if config is invalid).
###############################################################################
SSL_VAL=$(doveconf -h ssl 2>/dev/null | tr -d '[:space:]')
if [ "$SSL_VAL" != "required" ]; then
    echo "FAIL [PoC 2]: dovecot ssl is '$SSL_VAL', expected 'required' (plaintext still allowed)." >&2
    exit 1
fi
echo "PASS [PoC 2]: dovecot enforces ssl = required."

###############################################################################
# PoC 3: login_trusted_networks must be restricted to a specific network
# (not empty, not 0.0.0.0/0).
###############################################################################
LTN=$(doveconf -h login_trusted_networks 2>/dev/null | tr -d '[:space:]')
if [ -z "$LTN" ] || echo "$LTN" | grep -q '0\.0\.0\.0/0'; then
    echo "FAIL [PoC 3]: login_trusted_networks is empty or wildcarded ('$LTN')." >&2
    exit 1
fi
echo "PASS [PoC 3]: login_trusted_networks is restricted ('$LTN')."

###############################################################################
# Regression: dovecot must still be RUNNING and reachable on 143 from loopback.
# We prove liveness by reading the real IMAP greeting off the socket (procps is
# absent in this image, so we do NOT rely on pgrep/ps). A dead or over-blocked
# daemon yields no greeting and fails here.
###############################################################################
# Read the IMAP greeting off a loopback TCP connection using bash /dev/tcp
# (python is not installed in this image). A live dovecot greets with "* OK ...".
imap_greets() {
    exec 3<>/dev/tcp/127.0.0.1/143 || return 1
    local line=""
    read -t 3 -r line <&3
    exec 3<&- 3>&- 2>/dev/null || true
    printf '%s' "$line" | grep -q "OK"
}

for i in 1 2 3 4 5; do
    if imap_greets; then
        echo "PASS [Regression]: dovecot is alive and greets IMAP clients on 143 from loopback."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: dovecot not reachable on 143 from loopback." >&2
exit 1
