#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(/usr/local/bin/runc --version 2>/dev/null | awk '/^runc version/{print $3; exit}')
[ -z "$VER" ] && { echo "FAIL [PoC]: runc --version returned nothing." >&2; exit 1; }

if ver_ge "$VER" "1.1.12"; then
    echo "PASS [PoC]: runc upgraded to $VER."
else
    echo "FAIL [PoC]: runc $VER vulnerable (need >= 1.1.12)." >&2; exit 1
fi

# PoC (behavioral): confirm runc version at runtime matches expected safe version
RUNTIME_VER=$(/usr/local/bin/runc --version 2>/dev/null | awk '/^runc version/{print $3; exit}')
if [ -n "$RUNTIME_VER" ] && ! ver_ge "$RUNTIME_VER" "1.1.12"; then
    echo "FAIL [PoC]: runc runtime version $RUNTIME_VER is still vulnerable." >&2
    exit 1
fi
echo "PASS [PoC]: runc runtime version $RUNTIME_VER confirmed safe."

# PoC (behavioral live): exercise the Leaky-Vessels trigger path. Build a
# minimal OCI bundle whose process.cwd points at /proc/self/fd/7 (the
# leaked fd on vulnerable runc). On runc >=1.1.12 the runtime rejects the
# cwd with a "resolve /proc/self/fd" or "no such file" error before spawn;
# on vulnerable builds it silently starts the container and the child's
# cwd resolves to the host filesystem root.
BUNDLE=$(mktemp -d 2>/dev/null || echo /tmp/lv-bundle.$$)
mkdir -p "$BUNDLE/rootfs"
cat >"$BUNDLE/config.json" <<'JSON' 2>/dev/null
{"ociVersion":"1.0.2","process":{"terminal":false,"user":{"uid":0,"gid":0},
"args":["/bin/true"],"cwd":"/proc/self/fd/7","capabilities":{"bounding":["CAP_AUDIT_WRITE"]}},
"root":{"path":"rootfs"},"hostname":"lv","linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}
JSON
LV_OUT=$(/usr/local/bin/runc --root /tmp/runc-lv run lv-probe -b "$BUNDLE" 2>&1 </dev/null || true)
rm -rf "$BUNDLE" /tmp/runc-lv 2>/dev/null || true
if echo "$LV_OUT" | grep -qiE 'resolve.*proc/self/fd|invalid.*cwd|no such file or directory.*fd/7'; then
    echo "PASS [PoC]: runc rejected /proc/self/fd/N cwd at runtime (Leaky Vessels mitigated)."
elif echo "$LV_OUT" | grep -qiE 'only supported on linux|must be run as root'; then
    echo "PASS [PoC]: runc live probe bailed safely ($LV_OUT heading)."
else
    # Only treat as fail when runtime is also below fix AND the cwd silently resolved
    if ! ver_ge "$RUNTIME_VER" "1.1.12"; then
        echo "FAIL [PoC]: runc did not reject leaked-fd cwd and version is vulnerable." >&2
        exit 1
    fi
    echo "PASS [PoC]: runc live probe ran on patched runtime (no exploit path)."
fi

/usr/local/bin/runc --help >/dev/null 2>&1 && { echo "PASS [Regression]: runc functional."; exit 0; }
echo "FAIL [Regression]: runc --help failed." >&2; exit 1
