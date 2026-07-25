#!/bin/bash
# Verification: Scenario 07 - Drupalgeddon SQLi in expandArguments (CVE-2014-3704)
# VulnHub Source: DC-1
#
# Exit 0 = remediated (malicious array KEY cannot inject into the query) AND the
#          function still expands legitimate array arguments
# Exit 1 = still vulnerable (malicious key is injected) OR the function is broken
#
# Dynamic evidence: we EXECUTE the real expandArguments() from the live
# database.inc via php-cli and feed it the actual Drupalgeddon vector - an array
# argument whose sub-KEY carries injection characters. If the key reaches the
# output query, injection is possible. PHP re-includes the file on every call,
# so this reflects the current code with no restart involved.

PASS=true
DB_INC=/var/www/html/includes/database/database.inc
PROBE=/tmp/sr_drupal_probe_$$.php

cleanup() { rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

if ! command -v php >/dev/null 2>&1; then
    echo "FAIL: php CLI missing - cannot execute the expandArguments probe."; exit 1
fi
if [ ! -f "$DB_INC" ]; then
    echo "FAIL [PoC]: $DB_INC not found."; exit 1
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

if printf '%s' "$OUT" | grep -q 'NO_FUNC'; then
    echo "FAIL: expandArguments() is not defined in database.inc."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# --- Regression: legitimate array args must still expand into numbered keys ---
if printf '%s' "$LEGIT" | grep -q ':vals_0' && printf '%s' "$LEGIT" | grep -q ':vals_1'; then
    echo "PASS [Regression]: legitimate array arguments still expand correctly."
else
    echo "FAIL [Regression]: legitimate expansion is broken (over-aggressive patch?)."
    PASS=false
fi

# --- PoC: the malicious key must NOT appear in the resulting query ---
if printf '%s' "$MAL" | grep -q 'SR_PWNED'; then
    echo "FAIL [PoC]: malicious array key was injected into the query - still vulnerable."
    PASS=false
else
    echo "PASS [PoC]: malicious array key was rejected (no injection into the query)."
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
