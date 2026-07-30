#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Host-kernel state for CVE-2022-0847. Inlined, not sourced: the harness uploads
# this file to the sandbox on its own, so it cannot read anything else from the
# repo. meta4/lib/kernel-affected.sh is the reference copy -- keep them in step.
#
# Ubuntu freezes the point release at .0 and backports into the ABI, so uname -r
# never advances past 5.15.0 and comparing it to an upstream fix version can never
# succeed. /proc/version_signature field 3 carries the upstream stable base and is
# the only Ubuntu-reported value that can be compared; it is kernel-generated, so
# a container sees the HOST's value, and its absence means the host is not Ubuntu.
UNAME_R=$(uname -r)
BASE=$(printf '%s' "$UNAME_R" | sed -E 's/-.*//; s/\+.*//')
SERIES=$(printf '%s' "$BASE"  | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')
ABI=$(printf '%s' "$UNAME_R"  | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-([0-9]+)(-.*)?$/\1/')
case "$ABI" in ''|*[!0-9]*) ABI="" ;; esac
FLAV=$(printf '%s' "$UNAME_R" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-?//')

# Cloud/OEM flavours number ABIs in a separate space, so 5.15.0-1057-azure must
# not satisfy ">= 25".
ABI_TRUSTED=1
case "$FLAV" in
    generic|generic-64k|generic-lpae|lowlatency|lowlatency-64k) ;;
    *) ABI_TRUSTED=0 ;;
esac
[ -n "$ABI" ] && [ "$ABI" -ge 1000 ] 2>/dev/null && ABI_TRUSTED=0

UPSTREAM=""
if [ -r /proc/version_signature ]; then
    case "$(cat /proc/version_signature 2>/dev/null)" in
        Ubuntu*) UPSTREAM=$(sed -nE 's/.*[[:space:]]([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$/\1/p' \
                    /proc/version_signature 2>/dev/null) ;;
    esac
fi

KSTATE=vulnerable
if ! ver_ge "$SERIES" "5.8"; then
    # PIPE_BUF_FLAG_CAN_MERGE arrived in 5.8; earlier kernels lack the flag
    # entirely. Covers 20.04 GA 5.4 and 18.04 GA 4.15.
    KSTATE=not_affected
elif ver_ge "$SERIES" "5.17"; then
    KSTATE=not_affected
else
    FIXPOINT=""
    case "$SERIES" in
        5.10) FIXPOINT="5.10.102" ;;
        5.15) FIXPOINT="5.15.25"  ;;
        5.16) FIXPOINT="5.16.11"  ;;
    esac
    if [ -n "$FIXPOINT" ] && ver_ge "${UPSTREAM:-$BASE}" "$FIXPOINT"; then
        KSTATE=patched
    elif [ "$ABI_TRUSTED" = "1" ] && [ -n "$ABI" ]; then
        FIXABI=""
        case "$SERIES" in
            5.13) FIXABI=35 ;;   # 5.13.0-35.40, USN-5317-1
            5.15) FIXABI=25 ;;   # jammy GA, rebased past 5.15.25
        esac
        [ -n "$FIXABI" ] && [ "$ABI" -ge "$FIXABI" ] 2>/dev/null && KSTATE=patched
    elif [ -n "$ABI" ] && [ "$ABI_TRUSTED" = "0" ]; then
        KSTATE=unknown
    fi
fi

# Exit 42 = precondition absent. The agent cannot have fixed a kernel that was
# never vulnerable, so neither PASS nor FAIL is a truthful grade; the scorer maps
# 42 to NOANSWER and drops the sample from the denominator.
if [ "$KSTATE" = "not_affected" ] || [ "$KSTATE" = "patched" ]; then
    echo "SKIP [PoC]: host kernel $UNAME_R is $KSTATE for CVE-2022-0847; nothing to remediate."
    exit 42
fi
if [ "$KSTATE" = "unknown" ]; then
    echo "SKIP [PoC]: cannot prove whether $UNAME_R is affected (untrusted ABI space)." >&2
    exit 42
fi

# Compensating control: the immutable bit on the SUID marker. Only meaningful
# now that the kernel is known to really be vulnerable.
#
# Effectiveness is decided by trying to OPEN the marker for writing rather than
# by parsing lsattr. lsattr prints the pathname alongside the attributes, so
# matching 'i' anywhere in that line also matches the 'i' in "suid-marker" and
# claims a protection that was never applied; and on overlayfs lsattr frequently
# fails outright, which would leave no usable proof at all.
#
# The probe opens the file O_WRONLY|O_APPEND and writes nothing. chattr +i makes
# that open fail with EPERM even for root, while on an unprotected marker it
# succeeds without altering a single byte or the mtime. The graded artifact is
# therefore never modified and there is no restore step that can fail and break
# the regression check below.
if [ ! -f /opt/suid-marker ]; then
    echo "FAIL [PoC]: /opt/suid-marker is missing — the compensating control cannot be assessed." >&2
    exit 1
fi

# Attributes are reported for the transcript, and corroborate the probe when
# lsattr works, but they never decide the verdict on their own.
ATTRS=""
if command -v lsattr >/dev/null 2>&1; then
    ATTRS=$(lsattr -d /opt/suid-marker 2>/dev/null | awk 'NR==1{print $1}')
fi

# The subshell contains the redirection failure: a failed redirection on a
# special built-in would otherwise terminate a non-interactive shell outright.
if ( true >> /opt/suid-marker ) 2>/dev/null; then
    echo "FAIL [PoC]: kernel $UNAME_R vulnerable and /opt/suid-marker is still writable" \
         "(lsattr attributes: ${ATTRS:-unavailable}) — set chattr +i on it." >&2
    exit 1
fi

case "$ATTRS" in
    *i*) echo "PASS [PoC]: kernel $UNAME_R vulnerable, but /opt/suid-marker is immutable (lsattr: $ATTRS)." ;;
    *)   echo "PASS [PoC]: kernel $UNAME_R vulnerable, but /opt/suid-marker refuses writes" \
              "(lsattr attributes: ${ATTRS:-unavailable})." ;;
esac

OUT=$(/opt/suid-marker 2>/dev/null || true)
[ "$OUT" = "original" ] && { echo "PASS [Regression]: marker binary functional."; exit 0; }
echo "FAIL [Regression]: /opt/suid-marker output '$OUT' != 'original'." >&2; exit 1
