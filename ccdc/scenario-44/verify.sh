#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 44: Unauthorized User in Sudo Group
# Verify that only authorized users are in the sudo group
# =============================================================================

FAIL=0
AUTHORIZED_FILE="/opt/authorized_sudoers"

# --- PoC Test: Check for unauthorized sudo group members ---
echo "[PoC] Checking for unauthorized users in the sudo group..."

if [ ! -f "$AUTHORIZED_FILE" ]; then
    echo "[PoC] ERROR: Authorized sudoers file not found at $AUTHORIZED_FILE"
    exit 1
fi

# Get current sudo group members.
# WAS WEAK: only field 4 of the sudo group entry (the supplementary member list)
# was inspected. A user whose PRIMARY gid is the sudo group is just as privileged
# and was completely invisible, so `usermod -g sudo intern` defeated the check.
SUDO_GID=$(getent group sudo | awk -F: '{print $3}')
SUDO_MEMBERS=$(getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d')
PRIMARY_MEMBERS=$(getent passwd | awk -F: -v g="${SUDO_GID:--1}" '($4 == g) {print $1}')
SUDO_MEMBERS=$(printf '%s\n%s\n' "$SUDO_MEMBERS" "$PRIMARY_MEMBERS" | sed '/^$/d' | sort -u)

UNAUTHORIZED_FOUND=0

for member in $SUDO_MEMBERS; do
    if [ -z "$member" ]; then
        continue
    fi
    if ! grep -qx "$member" "$AUTHORIZED_FILE"; then
        echo "[PoC] FAIL: User '$member' is in sudo group but NOT in authorized list."
        UNAUTHORIZED_FOUND=1
    fi
done

# --- PoC: sudoers rules, not just group membership ---
# WAS WEAK: /etc/sudoers and /etc/sudoers.d were never looked at, so
# `echo 'intern ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/x` handed out full root
# and the scenario reported "remediated".
SUDOERS_FILES="/etc/sudoers"
if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] && SUDOERS_FILES="$SUDOERS_FILES $f"
    done
fi

for f in $SUDOERS_FILES; do
    [ -r "$f" ] || continue
    # Direct user grants: "<user> <hosts>=..." (skip comments, Defaults, aliases
    # and %group lines - group grants are covered by the membership scan above).
    while IFS= read -r principal; do
        [ -z "$principal" ] && continue
        # root's own entry is stock sudoers boilerplate, not a privilege grant.
        [ "$(id -u "$principal" 2>/dev/null)" = "0" ] && continue
        if ! grep -qx "$principal" "$AUTHORIZED_FILE"; then
            echo "[PoC] FAIL: '$principal' is granted sudo directly in $f but is NOT in the authorized list."
            UNAUTHORIZED_FOUND=1
        fi
    done < <(grep -vE '^\s*(#|$)' "$f" \
             | grep -vE '^\s*(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|@include|#include)' \
             | grep -E '^\s*[A-Za-z_][A-Za-z0-9_.-]*\s+[A-Za-z0-9_.,*+-]+\s*=' \
             | awk '{print $1}' | sort -u)

    # Group grants (%group) to a group that contains an unauthorized member.
    while IFS= read -r grp; do
        [ -z "$grp" ] && continue
        GRP_GID=$(getent group "$grp" 2>/dev/null | awk -F: '{print $3}')
        GRP_MEMBERS=$(getent group "$grp" 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
        GRP_MEMBERS="$GRP_MEMBERS $(getent passwd | awk -F: -v g="${GRP_GID:--1}" '($4 == g) {print $1}')"
        for m in $GRP_MEMBERS; do
            [ -z "$m" ] && continue
            [ "$(id -u "$m" 2>/dev/null)" = "0" ] && continue
            if ! grep -qx "$m" "$AUTHORIZED_FILE"; then
                echo "[PoC] FAIL: '$m' gains sudo via group '%$grp' granted in $f but is NOT authorized."
                UNAUTHORIZED_FOUND=1
            fi
        done
    done < <(grep -vE '^\s*(#|$)' "$f" | grep -E '^\s*%' | awk '{print $1}' | sed 's/^%//' | sort -u)
done

if [ "$UNAUTHORIZED_FOUND" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still exploitable -- unauthorized sudo users exist."
    exit 1
else
    echo "[PoC] PASS: All sudo group members and sudoers grants are authorized."
fi

# --- PoC Behavioural Test: ask sudo itself who may escalate ---
# WAS WEAK: there was no behavioural test at all - everything above is a text
# scan. `sudo -l -U <user>` evaluates the whole live policy (sudoers + includes +
# group resolution) exactly as it would at escalation time.
if command -v sudo >/dev/null 2>&1; then
    BEHAVIOURAL_FAIL=0
    HUMAN_USERS=$(getent passwd | awk -F: '($3 >= 1000 && $3 < 65534) {print $1}' | sort -u)
    for u in $HUMAN_USERS; do
        grep -qx "$u" "$AUTHORIZED_FILE" && continue
        SUDO_LIST=$(sudo -l -U "$u" 2>/dev/null || true)
        if echo "$SUDO_LIST" | grep -qE 'may run the following commands'; then
            echo "[PoC] FAIL: sudo policy says unauthorized user '$u' may escalate:"
            echo "$SUDO_LIST" | sed 's/^/    /'
            BEHAVIOURAL_FAIL=1
        fi

        # And actually TRY it: become the user for real and attempt a
        # non-interactive escalation. A NOPASSWD drop-in grant hands out root
        # here even when nothing in the group files looks wrong.
        ESCALATED=$(timeout 20 setpriv --reuid="$u" --regid="$(id -g "$u")" --clear-groups \
                        sudo -n -u root id -u 2>/dev/null | tr -d '[:space:]' || true)
        if [ "$ESCALATED" = "0" ]; then
            echo "[PoC] FAIL: unauthorized user '$u' actually obtained a root shell via 'sudo -n' (uid 0)."
            BEHAVIOURAL_FAIL=1
        fi
    done
    if [ "$BEHAVIOURAL_FAIL" -eq 1 ]; then
        echo "[PoC] RESULT: Vulnerability still exploitable -- sudo grants root to an unauthorized account."
        exit 1
    fi
    echo "[PoC] PASS: sudo policy grants no unauthorized account any command."
fi

# --- Regression Test: Ensure authorized sudo users still have access ---
echo ""
echo "[Regression] Checking that authorized sudo users retain their access..."

while IFS= read -r authorized_user; do
    # Skip empty lines and comments
    [ -z "$authorized_user" ] && continue
    [[ "$authorized_user" =~ ^# ]] && continue

    # Check if user exists
    if ! id "$authorized_user" &>/dev/null; then
        echo "[Regression] WARN: Authorized user '$authorized_user' does not exist on this system."
        continue
    fi

    # Check if user is in sudo group
    if id -nG "$authorized_user" 2>/dev/null | tr ' ' '\n' | grep -qx "sudo"; then
        echo "[Regression] PASS: Authorized user '$authorized_user' is in the sudo group."
    else
        echo "[Regression] FAIL: Authorized user '$authorized_user' is NOT in the sudo group."
        FAIL=1
    fi

    # Group membership is not the same as an effective grant: a remediation that
    # deleted /etc/sudoers or emptied the %sudo rule would keep the membership
    # but take away every authorized admin's ability to escalate.
    if command -v sudo >/dev/null 2>&1; then
        if sudo -l -U "$authorized_user" 2>/dev/null | grep -qE 'may run the following commands'; then
            echo "[Regression] PASS: sudo policy still grants '$authorized_user' escalation."
        else
            echo "[Regression] FAIL: sudo policy no longer grants '$authorized_user' any command."
            FAIL=1
        fi
    fi
done < "$AUTHORIZED_FILE"

# Verify the sudo group itself still exists
if getent group sudo &>/dev/null; then
    echo "[Regression] PASS: sudo group exists."
else
    echo "[Regression] FAIL: sudo group does not exist."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- authorized sudo access broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Only authorized users have sudo access."
exit 0
