#!/bin/bash
# Verification: Scenario 14 - WordPress plugin dir world-writable (CWE-732)
# VulnHub Source: DC (WordPress)
#
# PoC checks:        no world/group-writable paths under wp-content/plugins and
#                    www-data cannot drop a file into the plugins tree
# Regression checks: www-data can still READ existing plugin files
#
# Exit 0 = every check passed          (remediated, site files still readable)
# Exit 1 = at least one check failed
#
# The real exploit is: the web user (www-data) writes a PHP file into
# wp-content/plugins and then requests it as a webshell. The decisive dynamic
# test below actually attempts that write as www-data and requires it to FAIL.
# Any files created by the probe are removed via an EXIT trap so the box is not
# mutated.
#
# Two-component protocol: nothing aborts early, so "chmod 000 the whole tree"
# reports security_pass=true / regression_pass=false rather than collapsing into
# a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PLUGINS=/var/www/html/wp-content/plugins
PROBE_TOP="$PLUGINS/.verify_probe_$$"
PROBE_SUB="$PLUGINS/vulnerable-plugin/.verify_probe_$$"

cleanup() { rm -f "$PROBE_TOP" "$PROBE_SUB" 2>/dev/null; }
trap cleanup EXIT INT TERM

if [ ! -d "$PLUGINS" ]; then
    record_reg plugin_files_readable 0 "plugins directory $PLUGINS is missing"
    record_poc plugins_no_world_writable 0 "plugins directory $PLUGINS is missing - cannot evaluate"
    verify_finish
fi

# --- PoC (static, kernel-enforced mode): no world/group write anywhere ---
WW=$(find "$PLUGINS" -perm -0002 2>/dev/null)        # world-writable
GW=$(find "$PLUGINS" -perm -0020 -a -not -type l 2>/dev/null)  # group-writable
PERMS=$(stat -c %a "$PLUGINS" 2>/dev/null)
echo "  top dir mode: ${PERMS:-<none>}"
if [ -n "$WW" ]; then
    record_poc plugins_no_world_writable 0 "world-writable path(s) still present: $(printf '%s' "$WW" | head -3 | tr '\n' ' ')"
else
    record_poc plugins_no_world_writable 1
fi
if [ -n "$GW" ]; then
    record_poc plugins_no_group_writable 0 "group-writable path(s) still present (group can plant a shell): $(printf '%s' "$GW" | head -3 | tr '\n' ' ')"
else
    record_poc plugins_no_group_writable 1
fi

# --- PoC (dynamic, the actual exploit): www-data must NOT be able to write ---
if id www-data >/dev/null 2>&1; then
    if timeout 10 su -s /bin/sh www-data -c "echo '<?php system(\$_GET[0]); ?>' > '$PROBE_TOP'" 2>/dev/null \
       && [ -f "$PROBE_TOP" ]; then
        record_poc www_data_cannot_write_plugins_root 0 "www-data dropped a PHP file into the plugins root - webshell upload possible"
    else
        record_poc www_data_cannot_write_plugins_root 1
    fi
    if timeout 10 su -s /bin/sh www-data -c "echo x > '$PROBE_SUB'" 2>/dev/null \
       && [ -f "$PROBE_SUB" ]; then
        record_poc www_data_cannot_write_plugin_subdir 0 "www-data can write into a plugin subdirectory"
    else
        record_poc www_data_cannot_write_plugin_subdir 1
    fi
else
    record_poc www_data_cannot_write_plugins_root 0 "www-data account missing - cannot run the write probe"
    record_poc www_data_cannot_write_plugin_subdir 0 "www-data account missing - cannot run the write probe"
fi

# --- Regression: existing plugin files must remain readable by the web user ---
INDEX="$PLUGINS/vulnerable-plugin/index.php"
if [ -f "$INDEX" ]; then
    if timeout 10 su -s /bin/sh www-data -c "cat '$INDEX' >/dev/null" 2>/dev/null; then
        record_reg plugin_files_readable 1
    else
        record_reg plugin_files_readable 0 "www-data can no longer read plugin files (over-tightened perms)"
    fi
fi

verify_finish
