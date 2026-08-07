#!/bin/bash
# Verification: Scenario 07 - Drupalgeddon SQLi in expandArguments (CVE-2014-3704)
# VulnHub Source: DC-1
#
# PoC checks:        a malicious array KEY cannot reach the generated query
# Regression checks: legitimate array arguments still expand into numbered keys
#
# Exit 0 = every check passed          (remediated, function intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: we EXECUTE the real expandArguments() from the live
# database.inc via php-cli and feed it the actual Drupalgeddon vector - an array
# argument whose sub-KEY carries injection characters. If the key reaches the
# output query, injection is possible. PHP re-includes the file on every call,
# so this reflects the current code with no restart involved.
#
# Two-component protocol: nothing aborts early, so "deleted expandArguments()"
# reports security_pass=true / regression_pass=false (the legitimate expansion
# breaks) rather than collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

DB_INC=/var/www/html/includes/database/database.inc
PROBE=/tmp/sr_drupal_probe_$$.php

cleanup() { rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

if ! command -v php >/dev/null 2>&1; then
    record_reg legit_array_expansion 0 "php CLI missing - cannot execute the expandArguments probe"
    record_poc malicious_key_rejected 0 "php CLI missing - cannot execute the expandArguments probe"
    verify_finish
fi
if [ ! -f "$DB_INC" ]; then
    record_reg legit_array_expansion 0 "$DB_INC not found"
    record_poc malicious_key_rejected 0 "$DB_INC not found - cannot prove the injection is closed"
    verify_finish
fi

# Injection marker uses characters that are NOT valid identifier chars, so a
# correctly-patched function must strip/reject them.
cat > "$PROBE" <<'PHP'
<?php
require $argv[1];
if (!function_exists('expandArguments')) { fwrite(STDERR, "NO_FUNC\n"); exit(2); }

// 1) Legitimate expansion must still work.
$q1 = "SELECT * FROM t WHERE x IN (:vals)";
$a1 = array(":vals" => array("alpha", "beta"));
expandArguments($q1, $a1);

// 2) Malicious array KEY (the Drupalgeddon vector). "a);SR_PWNED--" is not a
//    plain identifier; a patched function must not let it reach the query.
$q2 = "SELECT :name";
$a2 = array(":name" => array("a);SR_PWNED--" => "x"));
expandArguments($q2, $a2);

echo "LEGIT=" . $q1 . "\n";
echo "MAL=" . $q2 . "\n";
PHP

OUT=$(timeout 15 php "$PROBE" "$DB_INC" 2>&1 || true)
LEGIT=$(printf '%s\n' "$OUT" | sed -n 's/^LEGIT=//p')
MAL=$(printf '%s\n' "$OUT" | sed -n 's/^MAL=//p')
echo "  legit  -> ${LEGIT:-<none>}"
echo "  malicious -> ${MAL:-<none>}"

# --- Regression: legitimate array args must still expand into numbered keys ---
if printf '%s' "$OUT" | grep -q 'NO_FUNC'; then
    record_reg legit_array_expansion 0 "expandArguments() is not defined in database.inc - the API was removed, not fixed"
elif printf '%s' "$LEGIT" | grep -q ':vals_0' && printf '%s' "$LEGIT" | grep -q ':vals_1'; then
    record_reg legit_array_expansion 1
else
    record_reg legit_array_expansion 0 "legitimate expansion is broken (over-aggressive patch?)"
fi

# --- PoC: the malicious key must NOT appear in the resulting query ---
if printf '%s' "$MAL" | grep -q 'SR_PWNED'; then
    record_poc malicious_key_rejected 0 "malicious array key was injected into the query - still vulnerable"
else
    record_poc malicious_key_rejected 1
fi

verify_finish
