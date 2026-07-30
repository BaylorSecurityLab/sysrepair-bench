#!/bin/sh
# ---------------------------------------------------------------------------
# CVE-2023-2640 / CVE-2023-32629 -- GameOver(lay), Ubuntu OverlayFS LPE.
#
# Inlined, not sourced: the harness uploads this file to the sandbox on its own,
# so it cannot read anything else from the repo. meta4/lib/kernel-affected.sh is
# the reference copy of the uname/ABI parsing -- keep them in step.
# ---------------------------------------------------------------------------
set -u

UNAME_R=$(uname -r)
BASE=$(printf '%s' "$UNAME_R" | sed -E 's/-.*//; s/\+.*//')
SERIES=$(printf '%s' "$BASE"  | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')
ABI=$(printf '%s' "$UNAME_R"  | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-([0-9]+)(-.*)?$/\1/')
case "$ABI" in ''|*[!0-9]*) ABI="" ;; esac
FLAV=$(printf '%s' "$UNAME_R" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-?//')

# Cloud/OEM flavours number their ABI in a SEPARATE space, so 5.15.0-1057-azure
# must not satisfy ">= 177". Refuse ABI proofs for them rather than reading 1057
# as newer than the generic-flavour threshold.
ABI_TRUSTED=1
case "$FLAV" in
    generic|generic-64k|generic-lpae|lowlatency|lowlatency-64k) ;;
    *) ABI_TRUSTED=0 ;;
esac
[ -n "$ABI" ] && [ "$ABI" -ge 1000 ] 2>/dev/null && ABI_TRUSTED=0

# The flaw is in Ubuntu's SAUCE overlayfs patches, so a non-Ubuntu host is not
# affected at all. /proc/version_signature is kernel-generated, so a container
# sees the HOST's value; its absence means the host kernel is not Ubuntu.
IS_UBUNTU=0
if [ -r /proc/version_signature ]; then
    case "$(cat /proc/version_signature 2>/dev/null)" in Ubuntu*) IS_UBUNTU=1 ;; esac
fi

# Ubuntu security tracker fixed versions (ubuntu.com/security/CVE-2023-2640):
#   linux          jammy  5.15.0-177.187  -> 177
#   linux-hwe-5.19 jammy  5.19.0-50.50    -> 50
#   linux          lunar  6.2.0-26.26     -> 26
# Every other Ubuntu series (4.4, 4.15, 5.4, 6.5, 6.8+) is marked "Not affected":
# the flawed SAUCE patch only ever shipped in these three lines.
#
# The jammy bar is 177 rather than any earlier number because the fix IS the
# removal of the flawed patch: the 5.15.0-177.187 changelog carries
# 'Revert "UBUNTU: SAUCE: overlayfs: Skip permission checking for
# trusted.overlayfs.* xattrs"' under the CVE-2023-2640 // CVE-2023-32629
# heading. A patch cannot be reverted unless it was present, which is what makes
# every jammy 5.15 below 177 affected.
#
# Note that the widely reproduced PoC (setcap inside `unshare -rm`, then overlay
# copy-up) does NOT yield root on jammy 5.15: the copied-up security.capability
# is VFS_CAP_REVISION_3 carrying rootid=<uid>, so it is only honoured inside a
# userns owned by that uid and is ignored in the init namespace. That is why some
# third-party tables list jammy 5.15.0 as unaffected. It measures PoC
# exploitability, not the presence of the flawed patch, so the vendor's fixed
# version governs here -- and a behavioural exploit attempt must never be the
# source of the verdict, or a vendor-affected host would grade as safe.
FIXABI=""
case "$SERIES" in
    5.15) FIXABI=177 ;;
    5.19) FIXABI=50  ;;
    6.2)  FIXABI=26  ;;
esac

KSTATE=vulnerable
if [ "$IS_UBUNTU" = "0" ] || [ -z "$FIXABI" ]; then
    KSTATE=not_affected
elif [ "$ABI_TRUSTED" = "0" ] || [ -z "$ABI" ]; then
    KSTATE=unknown
elif [ "$ABI" -ge "$FIXABI" ] 2>/dev/null; then
    KSTATE=patched
fi

# Exit 42 = precondition absent. The container shares the host kernel and cannot
# upgrade it, so the host's patch level is a state the agent could not have
# created; neither PASS nor FAIL would be a truthful grade. scorer.py maps 42 to
# NOANSWER and drops the sample from the denominator.
case "$KSTATE" in
    not_affected)
        echo "SKIP [PoC]: host kernel $UNAME_R is not affected by CVE-2023-2640/32629; nothing to remediate."
        exit 42 ;;
    patched)
        echo "SKIP [PoC]: host kernel $UNAME_R is already patched (ABI $ABI >= $FIXABI); nothing to remediate."
        exit 42 ;;
    unknown)
        echo "SKIP [PoC]: cannot prove whether $UNAME_R is affected -- ABI '${ABI:-none}' is not in the generic-flavour numbering space that threshold ${FIXABI:-n/a} belongs to." >&2
        exit 42 ;;
esac

# Behavioural probe: can an unprivileged uid still create a user namespace?
#
# setpriv, not su: su needs an existing account and goes through PAM, so a
# missing user, a PAM refusal or an absent su binary is indistinguishable from
# the kernel refusing the namespace -- which is how an unremediated host could
# read as protected. The first run drops privileges WITHOUT asking for a
# namespace; only if that succeeds is a failure of the second run attributable
# to the kernel. If the probe cannot be set up at all it stays inconclusive and
# never counts as evidence of remediation.
USERNS=inconclusive
if command -v setpriv >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1; then
    if setpriv --reuid=65534 --regid=65534 --clear-groups true 2>/dev/null; then
        if setpriv --reuid=65534 --regid=65534 --clear-groups unshare -U true 2>/dev/null; then
            USERNS=open
        else
            USERNS=blocked
        fi
    fi
fi

# Documented mitigation for this CVE: remove the unprivileged user namespace the
# exploit needs for its overlayfs mount. Both knobs achieve that.
UC=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "")
MAXNS=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "")
CONTROL=""
[ "$UC" = "0" ] && CONTROL="kernel.unprivileged_userns_clone=0"
[ "$MAXNS" = "0" ] && CONTROL="${CONTROL:+$CONTROL, }user.max_user_namespaces=0"

VULN="kernel $UNAME_R vulnerable (ABI $ABI < $FIXABI)"
case "$USERNS" in
    open)
        echo "FAIL [PoC]: $VULN and an unprivileged uid can still create a user namespace" \
             "-- the OverlayFS copy-up LPE surface is open." >&2
        exit 1 ;;
    blocked)
        echo "PASS [PoC]: $VULN, but an unprivileged uid is refused a user namespace" \
             "(${CONTROL:-no sysctl knob set; refused by another mechanism})." ;;
    *)
        if [ -z "$CONTROL" ]; then
            echo "FAIL [PoC]: $VULN, no userns restriction is set, and the behavioural probe" \
                 "could not run -- remediation is unproven." >&2
            exit 1
        fi
        echo "PASS [PoC]: $VULN, but unprivileged user namespaces are restricted ($CONTROL);" \
             "behavioural probe unavailable in this container." ;;
esac

/opt/marker-bash -c 'exit 0' 2>/dev/null && { echo "PASS [Regression]: /opt/marker-bash executes."; exit 0; }
echo "FAIL [Regression]: /opt/marker-bash no longer executes." >&2
exit 1
