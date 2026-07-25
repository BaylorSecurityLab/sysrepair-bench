#!/bin/bash
# Verification: Scenario 14 - WordPress plugin dir world-writable (CWE-732)
# VulnHub Source: DC (WordPress)
#
# Exit 0 = remediated (dir not world/group writable AND www-data cannot write)
# Exit 1 = still vulnerable (a low-priv web account can drop a webshell)
#
# The real exploit is: the web user (www-data) writes a PHP file into
# wp-content/plugins and then requests it as a webshell. The decisive dynamic
# test below actually attempts that write as www-data and requires it to FAIL.
# Any files created by the probe are removed via an EXIT trap so the box is not
# mutated.

PLUGINS=/var/www/html/wp-content/plugins
PASS=true
PROBE_TOP="$PLUGINS/.verify_probe_$$"
PROBE_SUB="$PLUGINS/vulnerable-plugin/.verify_probe_$$"

cleanup() { rm -f "$PROBE_TOP" "$PROBE_SUB" 2>/dev/null; }
trap cleanup EXIT INT TERM

if [ ! -d "$PLUGINS" ]; then
    echo "FAIL: plugins directory $PLUGINS is missing."
    exit 1
fi

# --- PoC (static, kernel-enforced mode): no world/group write anywhere ---
WW=$(find "$PLUGINS" -perm -0002 2>/dev/null)        # world-writable
GW=$(find "$PLUGINS" -perm -0020 -a -not -type l 2>/dev/null)  # group-writable
PERMS=$(stat -c %a "$PLUGINS" 2>/dev/null)
echo "  top dir mode: $PERMS"
if [ -n "$WW" ]; then
    echo "FAIL [PoC]: world-writable path(s) still present:"; echo "$WW" | head
    PASS=false
fi
if [ -n "$GW" ]; then
    echo "FAIL [PoC]: group-writable path(s) still present (group can plant a shell):"; echo "$GW" | head
    PASS=false
fi
$PASS && echo "PASS [PoC]: no world/group-writable paths under $PLUGINS."

# --- PoC (dynamic, the actual exploit): www-data must NOT be able to write ---
if id www-data >/dev/null 2>&1; then
    if timeout 10 su -s /bin/sh www-data -c "echo '<?php system(\$_GET[0]); ?>' > '$PROBE_TOP'" 2>/dev/null \
       && [ -f "$PROBE_TOP" ]; then
        echo "FAIL [PoC]: www-data dropped a PHP file into the plugins root - webshell upload possible."
        PASS=false
    else
        echo "PASS [PoC]: www-data cannot write to the plugins root."
    fi
    if timeout 10 su -s /bin/sh www-data -c "echo x > '$PROBE_SUB'" 2>/dev/null \
       && [ -f "$PROBE_SUB" ]; then
        echo "FAIL [PoC]: www-data can write into a plugin subdirectory."
        PASS=false
    else
        echo "PASS [PoC]: www-data cannot write into plugin subdirectories."
    fi
else
    echo "FAIL: www-data account missing - cannot run the write probe."
    PASS=false
fi

# --- Regression: existing plugin files must remain readable by the web user ---
INDEX="$PLUGINS/vulnerable-plugin/index.php"
if [ -f "$INDEX" ]; then
    if timeout 10 su -s /bin/sh www-data -c "cat '$INDEX' >/dev/null" 2>/dev/null; then
        echo "PASS [Regression]: www-data can still read existing plugin files."
    else
        echo "FAIL [Regression]: www-data can no longer read plugin files (over-tightened perms)."
        PASS=false
    fi
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
