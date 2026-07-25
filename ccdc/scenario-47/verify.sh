#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 47: No PAM Password Complexity (pwquality)
# Verify that password quality requirements are properly configured
# =============================================================================

FAIL=0
PWQUALITY_CONF="/etc/security/pwquality.conf"

# --- PoC Test: Check if password quality settings are too permissive ---
echo "[PoC] Checking password quality configuration..."

POC_FAIL=0

if [ ! -f "$PWQUALITY_CONF" ]; then
    echo "[PoC] FAIL: $PWQUALITY_CONF does not exist -- pwquality not configured."
    exit 1
fi

# Helper: get last effective value for a key (ignoring comments)
get_pwquality_val() {
    local key="$1"
    grep -E "^\s*${key}\s*=" "$PWQUALITY_CONF" | tail -1 | sed 's/.*=\s*//' | tr -d ' '
}

# Check minlen (should be >= 14)
MINLEN=$(get_pwquality_val "minlen")
if [ -z "$MINLEN" ]; then
    echo "[PoC] FAIL: minlen not set in $PWQUALITY_CONF."
    POC_FAIL=1
elif [ "$MINLEN" -lt 14 ]; then
    echo "[PoC] FAIL: minlen is $MINLEN (should be >= 14)."
    POC_FAIL=1
else
    echo "[PoC] PASS: minlen is $MINLEN (>= 14)."
fi

# Check the character-class credits (each should be <= -1, i.e. at least one
# character of that class is REQUIRED).
# WAS WEAK: an UNSET credit was scored PASS as "default". The libpwquality
# default is +1, which merely lets a character of that class earn one length
# credit - it does not require the class at all. Leaving dcredit/ucredit/
# lcredit/ocredit unset is therefore not compliant, and treating it as a pass
# meant "delete the weak lines and stop" scored as a full remediation. A credit
# must now be explicitly set to a negative value (or minclass must demand all
# four classes, which is the equivalent CIS formulation).
MINCLASS=$(get_pwquality_val "minclass")
CLASS_COVERED=false
if [ -n "$MINCLASS" ] && [ "$MINCLASS" -ge 4 ] 2>/dev/null; then
    CLASS_COVERED=true
    echo "[PoC] PASS: minclass is $MINCLASS (all four character classes required)."
fi

for key in dcredit ucredit lcredit ocredit; do
    VAL=$(get_pwquality_val "$key")
    if [ -z "$VAL" ]; then
        if $CLASS_COVERED; then
            echo "[PoC] PASS: $key not set, but minclass=$MINCLASS already requires that class."
        else
            echo "[PoC] FAIL: $key is not set - the pwquality default (+1) does NOT require that character class."
            POC_FAIL=1
        fi
    elif [ "$VAL" -ge 0 ] 2>/dev/null; then
        echo "[PoC] FAIL: $key is $VAL (should be <= -1 to require that character class)."
        POC_FAIL=1
    else
        echo "[PoC] PASS: $key is $VAL."
    fi
done

# Check enforcing (should be 1)
ENFORCING=$(get_pwquality_val "enforcing")
if [ "$ENFORCING" = "0" ]; then
    echo "[PoC] FAIL: enforcing is 0 (quality checks are not enforced)."
    POC_FAIL=1
else
    echo "[PoC] PASS: enforcing is ${ENFORCING:-(not set, default enforced)}."
fi

# Check dictcheck (should be 1 or not explicitly set to 0)
DICTCHECK=$(get_pwquality_val "dictcheck")
if [ "$DICTCHECK" = "0" ]; then
    echo "[PoC] FAIL: dictcheck is 0 (dictionary check disabled)."
    POC_FAIL=1
else
    echo "[PoC] PASS: dictcheck is ${DICTCHECK:-(not set, default enabled)}."
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- password complexity too permissive."
    exit 1
else
    echo "[PoC] PASS: Password quality settings meet security requirements."
fi

# --- PoC Behavioral Test: Verify PAM is configured with pam_pwquality ---
echo ""
echo "[PoC] Checking PAM configuration for pam_pwquality..."

PAM_PWQUALITY_FOUND=false
for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/passwd; do
    if [ -f "$pam_file" ] && grep -qE '^\s*(password\s+.*)?pam_pwquality\.so' "$pam_file" 2>/dev/null; then
        PAM_PWQUALITY_FOUND=true
        echo "[PoC] PASS: pam_pwquality.so is configured in $pam_file"

        # Verify key parameters are passed to the PAM module
        PAM_LINE=$(grep -E 'pam_pwquality\.so' "$pam_file" | grep -v '^\s*#' | tail -1)
        if echo "$PAM_LINE" | grep -q 'retry='; then
            echo "[PoC] PASS: retry parameter found in PAM config"
        else
            echo "[PoC] INFO: retry parameter not in PAM line (default applies)"
        fi
        break
    fi
done

if ! $PAM_PWQUALITY_FOUND; then
    echo "[PoC] FAIL: pam_pwquality.so not found in any PAM password config"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: PAM not properly configured for password quality."
    exit 1
fi

# --- PoC Behavioral Test: live pwquality enforcement through the real PAM stack ---
# WAS WEAK: this probe used pwscore (not installed - libpwquality-tools is absent)
# and therefore always fell through to cracklib-check with the password "a".
# cracklib-check rejects "a" as "WAY too short" from its own built-in rules,
# ignoring /etc/security/pwquality.conf entirely - so the "live enforcement" layer
# passed identically on the VULNERABLE baseline. It proved nothing.
#
# Instead, drive a real `passwd` as the unprivileged testuser over a pty and try
# to set a password that:
#   * pam_unix's `obscure` check accepts (12 chars, so not "too short"), and
#   * a compliant pwquality policy must reject (single character class, < 14).
# On the baseline (minlen=1, credits=0, enforcing=0) this password is ACCEPTED.
# The account's shadow entry is saved and restored around the probe.
echo ""
echo "[PoC] Probing live password-quality enforcement through PAM (passwd as testuser)..."

WEAK_CANDIDATE='abcdefghijkl'          # 12 chars, lowercase only - no digit/upper/special
PROBE_CURRENT='Zq7#vNp2Lk9@wTxR'       # complies with any sane policy
STRONG_CANDIDATE='Xk9#mQr2Vt7@Lp'      # 14 chars, all four classes

if command -v script >/dev/null 2>&1 && id testuser >/dev/null 2>&1; then
    SHADOW_BAK=$(mktemp /tmp/shadowbak.XXXXXX)
    cat /etc/shadow > "$SHADOW_BAK"

    # Root-driven chpasswd bypasses pam_pwquality (root is exempt), so this only
    # establishes a known current password for the probe.
    echo "testuser:${PROBE_CURRENT}" | chpasswd 2>/dev/null

    pw_change() {
        local newpw="$1"
        ( sleep 1; printf '%s\n' "$PROBE_CURRENT"
          sleep 1; printf '%s\n' "$newpw"
          sleep 1; printf '%s\n' "$newpw"
          sleep 2 ) | timeout 40 script -qec "su - testuser -c passwd" /dev/null 2>&1 | tr -d '\r' || true
    }

    WEAK_OUT=$(pw_change "$WEAK_CANDIDATE" || true)
    cat "$SHADOW_BAK" > /etc/shadow
    echo "testuser:${PROBE_CURRENT}" | chpasswd 2>/dev/null

    if echo "$WEAK_OUT" | grep -q 'password updated successfully'; then
        echo "[PoC] FAIL: PAM accepted the weak password '$WEAK_CANDIDATE' (12 chars, one character class)."
        POC_FAIL=1
    else
        echo "[PoC] PASS: PAM rejected the weak password '$WEAK_CANDIDATE'."
        echo "$WEAK_OUT" | grep -E 'BAD PASSWORD|must choose' | head -1 | sed 's/^/    /'
    fi

    # Regression side of the same probe: a genuinely strong password must still
    # be accepted, or the policy is unusable rather than merely strict.
    STRONG_OUT=$(pw_change "$STRONG_CANDIDATE" || true)
    if echo "$STRONG_OUT" | grep -q 'password updated successfully'; then
        echo "[PoC] PASS: PAM still accepts a compliant strong password."
    else
        echo "[PoC] FAIL: PAM rejected a compliant strong password - password changes are broken."
        echo "$STRONG_OUT" | grep -E 'BAD PASSWORD|must choose|error' | head -1 | sed 's/^/    /'
        POC_FAIL=1
    fi

    cat "$SHADOW_BAK" > /etc/shadow
    rm -f "$SHADOW_BAK"
else
    echo "[PoC] FAIL: cannot run the live enforcement probe (script(1) or testuser missing)."
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Live password-quality enforcement still accepts weak passwords."
    exit 1
fi

# --- Regression Test: Ensure password changes still work ---
echo ""
echo "[Regression] Checking that password management still functions..."

# Verify pwquality.conf exists and is readable
if [ -r "$PWQUALITY_CONF" ]; then
    echo "[Regression] PASS: $PWQUALITY_CONF is readable."
else
    echo "[Regression] FAIL: $PWQUALITY_CONF is not readable."
    FAIL=1
fi

# Verify pam_pwquality module is installed
if [ -f /usr/lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/security/pam_pwquality.so ]; then
    echo "[Regression] PASS: pam_pwquality module is installed."
else
    echo "[Regression] FAIL: pam_pwquality module not found."
    FAIL=1
fi

# Verify passwd command works
if command -v passwd &>/dev/null; then
    echo "[Regression] PASS: passwd command is available."
else
    echo "[Regression] FAIL: passwd command not found."
    FAIL=1
fi

# Verify testuser account exists
if id testuser &>/dev/null; then
    echo "[Regression] PASS: testuser account exists."
else
    echo "[Regression] FAIL: testuser account missing."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- password management broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Password complexity enforced and password management works."
exit 0
