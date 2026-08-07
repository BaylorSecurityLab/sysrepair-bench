#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 47: No PAM Password Complexity (pwquality)
# Verify that password quality requirements are properly configured
#
# PoC checks:        pwquality.conf demands a real policy, pam_pwquality is
#                    wired into the PAM stack, and a live `passwd` run really
#                    rejects a weak password
# Regression checks: password management still works - the module and tools are
#                    present and a compliant strong password is still accepted
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "tightened the policy so far that nobody can change their
# password" is reported as security_pass=true / regression_pass=false rather
# than collapsing into a bare exit 1. See lib/verifylib.sh.
#
# NOTE ON KINDS: the "a compliant strong password must still be accepted" probe
# was previously printed under a [PoC] label even though its own comment calls
# it "the regression side of the same probe". It proves the service still works,
# so it is recorded as a regression check. Same condition, same strictness.
# =============================================================================

PWQUALITY_CONF="/etc/security/pwquality.conf"

# --- PoC Test: Check if password quality settings are too permissive ---
echo "[PoC] Checking password quality configuration..."

if [ -f "$PWQUALITY_CONF" ]; then
    record_poc pwquality_conf_present 1
else
    record_poc pwquality_conf_present 0 "$PWQUALITY_CONF does not exist -- pwquality not configured"
fi

# Helper: get last effective value for a key (ignoring comments)
get_pwquality_val() {
    local key="$1"
    grep -E "^\s*${key}\s*=" "$PWQUALITY_CONF" 2>/dev/null | tail -1 | sed 's/.*=\s*//' | tr -d ' ' || true
}

# Check minlen (should be >= 14)
MINLEN=$(get_pwquality_val "minlen")
if [ -z "$MINLEN" ]; then
    record_poc minlen_at_least_14 0 "minlen not set in $PWQUALITY_CONF"
elif ! [ "$MINLEN" -ge 14 ] 2>/dev/null; then
    record_poc minlen_at_least_14 0 "minlen is $MINLEN (should be >= 14)"
else
    record_poc minlen_at_least_14 1
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
    echo "  [PoC] minclass is $MINCLASS (all four character classes required)."
fi

for key in dcredit ucredit lcredit ocredit; do
    VAL=$(get_pwquality_val "$key")
    if [ -z "$VAL" ]; then
        if $CLASS_COVERED; then
            record_poc "${key}_requires_class" 1
        else
            record_poc "${key}_requires_class" 0 "$key is not set - the pwquality default (+1) does NOT require that character class"
        fi
    elif [ "$VAL" -ge 0 ] 2>/dev/null; then
        record_poc "${key}_requires_class" 0 "$key is $VAL (should be <= -1 to require that character class)"
    else
        record_poc "${key}_requires_class" 1
    fi
done

# Check enforcing (should be 1)
ENFORCING=$(get_pwquality_val "enforcing")
if [ "$ENFORCING" = "0" ]; then
    record_poc pwquality_enforcing 0 "enforcing is 0 (quality checks are not enforced)"
else
    record_poc pwquality_enforcing 1
fi

# Check dictcheck (should be 1 or not explicitly set to 0)
DICTCHECK=$(get_pwquality_val "dictcheck")
if [ "$DICTCHECK" = "0" ]; then
    record_poc pwquality_dictcheck 0 "dictcheck is 0 (dictionary check disabled)"
else
    record_poc pwquality_dictcheck 1
fi

# --- PoC Behavioral Test: Verify PAM is configured with pam_pwquality ---
echo ""
echo "[PoC] Checking PAM configuration for pam_pwquality..."

PAM_PWQUALITY_FOUND=false
for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/passwd; do
    if [ -f "$pam_file" ] && grep -qE '^\s*(password\s+.*)?pam_pwquality\.so' "$pam_file" 2>/dev/null; then
        PAM_PWQUALITY_FOUND=true
        echo "  [PoC] pam_pwquality.so is configured in $pam_file"

        # Verify key parameters are passed to the PAM module
        PAM_LINE=$(grep -E 'pam_pwquality\.so' "$pam_file" | grep -v '^\s*#' | tail -1 || true)
        if echo "$PAM_LINE" | grep -q 'retry='; then
            echo "  [PoC] retry parameter found in PAM config"
        else
            echo "  [PoC] INFO: retry parameter not in PAM line (default applies)"
        fi
        break
    fi
done

if $PAM_PWQUALITY_FOUND; then
    record_poc pam_pwquality_configured 1
else
    record_poc pam_pwquality_configured 0 "pam_pwquality.so not found in any PAM password config"
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
        record_poc weak_password_rejected 0 "PAM accepted the weak password '$WEAK_CANDIDATE' (12 chars, one character class)"
    else
        record_poc weak_password_rejected 1
        echo "$WEAK_OUT" | grep -E 'BAD PASSWORD|must choose' | head -1 | sed 's/^/    /' || true
    fi

    # Regression side of the same probe: a genuinely strong password must still
    # be accepted, or the policy is unusable rather than merely strict.
    STRONG_OUT=$(pw_change "$STRONG_CANDIDATE" || true)
    if echo "$STRONG_OUT" | grep -q 'password updated successfully'; then
        record_reg strong_password_still_accepted 1
    else
        record_reg strong_password_still_accepted 0 "PAM rejected a compliant strong password - password changes are broken"
        echo "$STRONG_OUT" | grep -E 'BAD PASSWORD|must choose|error' | head -1 | sed 's/^/    /' || true
    fi

    cat "$SHADOW_BAK" > /etc/shadow
    rm -f "$SHADOW_BAK"
else
    record_poc weak_password_rejected 0 "cannot run the live enforcement probe (script(1) or testuser missing)"
fi

# --- Regression Test: Ensure password changes still work ---
echo ""
echo "[Regression] Checking that password management still functions..."

# Verify pwquality.conf exists and is readable
if [ -r "$PWQUALITY_CONF" ]; then
    record_reg pwquality_conf_readable 1
else
    record_reg pwquality_conf_readable 0 "$PWQUALITY_CONF is not readable"
fi

# Verify pam_pwquality module is installed
if [ -f /usr/lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/security/pam_pwquality.so ]; then
    record_reg pam_pwquality_module_installed 1
else
    record_reg pam_pwquality_module_installed 0 "pam_pwquality module not found"
fi

# Verify passwd command works
if command -v passwd &>/dev/null; then
    record_reg passwd_command_available 1
else
    record_reg passwd_command_available 0 "passwd command not found"
fi

# Verify testuser account exists
if id testuser &>/dev/null; then
    record_reg testuser_account_exists 1
else
    record_reg testuser_account_exists 0 "testuser account missing"
fi

verify_finish
