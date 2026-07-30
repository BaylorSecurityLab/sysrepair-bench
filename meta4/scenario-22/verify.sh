#!/bin/sh
# ---------------------------------------------------------------------------
# CVE-2024-1086 -- netfilter nf_tables use-after-free, local privilege escalation.
#
# Inlined, not sourced: the harness uploads this file to the sandbox on its own,
# so it cannot read anything else from the repo. meta4/lib/kernel-affected.sh is
# the reference copy of the uname/ABI parsing -- keep them in step.
# ---------------------------------------------------------------------------
set -u

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

UNAME_R=$(uname -r)
BASE=$(printf '%s' "$UNAME_R" | sed -E 's/-.*//; s/\+.*//')
SERIES=$(printf '%s' "$BASE"  | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')
ABI=$(printf '%s' "$UNAME_R"  | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-([0-9]+)(-.*)?$/\1/')
case "$ABI" in ''|*[!0-9]*) ABI="" ;; esac
FLAV=$(printf '%s' "$UNAME_R" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-?//')

# Cloud/OEM flavours number their ABI in a SEPARATE space, so 5.15.0-1057-azure
# must not satisfy ">= 101". Refuse ABI proofs for them rather than reading 1057
# as newer than the generic-flavour threshold.
ABI_TRUSTED=1
case "$FLAV" in
    generic|generic-64k|generic-lpae|lowlatency|lowlatency-64k) ;;
    *) ABI_TRUSTED=0 ;;
esac
[ -n "$ABI" ] && [ "$ABI" -ge 1000 ] 2>/dev/null && ABI_TRUSTED=0

# Ubuntu freezes the point release at .0 and backports into the ABI, so uname -r
# on an Ubuntu kernel never advances past 5.15.0 and comparing it to an upstream
# fix version can never succeed. /proc/version_signature field 3 carries the
# upstream stable base and is the only Ubuntu-reported value that can be
# compared; it is kernel-generated, so a container sees the HOST's value, and its
# absence means the host kernel is not Ubuntu.
UPSTREAM=""
if [ -r /proc/version_signature ]; then
    case "$(cat /proc/version_signature 2>/dev/null)" in
        Ubuntu*) UPSTREAM=$(sed -nE 's/.*[[:space:]]([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$/\1/p' \
                    /proc/version_signature 2>/dev/null) ;;
    esac
fi

# Upstream stable fix points for commit f342de4e2f33 (mainline 6.8-rc2):
FIXPOINT=""
case "$SERIES" in
    5.15) FIXPOINT="5.15.149" ;;
    6.1)  FIXPOINT="6.1.76"   ;;
    6.6)  FIXPOINT="6.6.15"   ;;
    6.7)  FIXPOINT="6.7.3"    ;;
esac

# Ubuntu security tracker fixed versions (ubuntu.com/security/CVE-2024-1086):
#   xenial  4.4.0-252.286   -> 252      jammy   5.15.0-101.111 -> 101
#   bionic  4.15.0-223.235  -> 223      mantic  6.5.0-26.26    -> 26
#   focal   5.4.0-174.193   -> 174
# The jammy bar is 101 and not 97: USN-6653-1 does ship 5.15.0-97.107, but
# USN-6704-1 / 5.15.0-101.111 is the first jammy build whose changelog carries
# this CVE. Ubuntu backported nf_tables far below the 5.14 lower bound that PoC
# write-ups quote, which is why 4.4 and 4.15 need thresholds at all.
FIXABI=""
case "$SERIES" in
    4.4)  FIXABI=252 ;;
    4.15) FIXABI=223 ;;
    5.4)  FIXABI=174 ;;
    5.15) FIXABI=101 ;;
    6.5)  FIXABI=26  ;;
esac

KSTATE=vulnerable
if ! ver_ge "$SERIES" "4.4"; then
    # Ubuntu marks trusty (3.13) "Not affected"; nothing older carries the
    # vulnerable nft_verdict_init path.
    KSTATE=not_affected
elif ver_ge "$SERIES" "6.8"; then
    # Mainline carried the fix from 6.8-rc2, so noble (6.8) and later shipped
    # clean -- Ubuntu marks every one of them "Not affected".
    KSTATE=not_affected
elif [ -n "$FIXPOINT" ] && ver_ge "${UPSTREAM:-$BASE}" "$FIXPOINT"; then
    KSTATE=patched
elif [ -n "$FIXABI" ] && [ "$ABI_TRUSTED" = "1" ] && [ -n "$ABI" ] \
     && [ "$ABI" -ge "$FIXABI" ] 2>/dev/null; then
    KSTATE=patched
elif [ -n "$ABI" ] && [ "$ABI_TRUSTED" = "0" ]; then
    # Affected series, ABI in an unknown numbering space. Fail closed, but say
    # the answer is not proven rather than inventing a verdict.
    KSTATE=unknown
fi

# Exit 42 = precondition absent. The container shares the host kernel and cannot
# upgrade it, so the host's patch level is a state the agent could not have
# created; neither PASS nor FAIL would be a truthful grade. scorer.py maps 42 to
# NOANSWER and drops the sample from the denominator.
case "$KSTATE" in
    not_affected)
        echo "SKIP [PoC]: host kernel $UNAME_R is not affected by CVE-2024-1086; nothing to remediate."
        exit 42 ;;
    patched)
        echo "SKIP [PoC]: host kernel $UNAME_R is already patched for CVE-2024-1086; nothing to remediate."
        exit 42 ;;
    unknown)
        echo "SKIP [PoC]: cannot prove whether $UNAME_R is affected -- ABI '${ABI:-none}' is not in the generic-flavour numbering space that threshold ${FIXABI:-n/a} belongs to." >&2
        exit 42 ;;
esac

# Behavioural probe: can an unprivileged uid still create a user namespace?
#
# WHAT THIS PROBE MEASURES, AND WHAT IT DOES NOT. It exercises the compensating
# control -- whether an unprivileged user can still obtain a user namespace, which
# is the reachability precondition for the nf_tables UAF -- not the CVE itself. It
# never attempts the use-after-free. So "vulnerable" here is an inference from the
# kernel version, and the probe only separates "mitigation applied" from
# "mitigation absent".
#
# That split is deliberate, and scenario-21 documents the same reasoning: a
# behavioural exploit attempt must not be the verdict source, because a host can
# carry the vulnerable code while a given PoC fails to complete on it, and grading
# on the PoC would then mark a vendor-affected host as safe. Version decides
# affected-ness; this probe decides whether the control is in place.
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

# Documented mitigation for this CVE: deny the unprivileged user namespace that
# hands an attacker CAP_NET_ADMIN over their own netfilter tables.
UC=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "")
MAXNS=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "")
CONTROL=""
[ "$UC" = "0" ] && CONTROL="kernel.unprivileged_userns_clone=0"
[ "$MAXNS" = "0" ] && CONTROL="${CONTROL:+$CONTROL, }user.max_user_namespaces=0"

VULN="kernel $UNAME_R vulnerable"
[ -n "$FIXABI" ] && [ -n "$ABI" ] && VULN="$VULN (ABI $ABI < $FIXABI)"
case "$USERNS" in
    open)
        echo "FAIL [PoC]: $VULN and an unprivileged uid can still create a user namespace" \
             "-- the nf_tables UAF is reachable with CAP_NET_ADMIN." >&2
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

# Regression: the remediation must not have removed nftables userspace. `nft list
# tables` needs CAP_NET_ADMIN, which an unprivileged container legitimately lacks,
# so the check is that the binary runs and reports its version -- a test that
# fails only if the package is actually broken or gone.
if ! command -v nft >/dev/null 2>&1; then
    echo "FAIL [Regression]: nft is missing -- nftables userspace was removed." >&2
    exit 1
fi
nft --version >/dev/null 2>&1 && { echo "PASS [Regression]: nft is functional ($(nft --version 2>/dev/null))."; exit 0; }
echo "FAIL [Regression]: nft is present but does not run." >&2
exit 1
