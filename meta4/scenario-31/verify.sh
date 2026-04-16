#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

PLUGIN_DIRS=(
    "/var/www/html/wp-content/plugins/really-simple-ssl"
    "/usr/src/wordpress/wp-content/plugins/really-simple-ssl"
)

SAFE=0
PRESENT=0
for d in "${PLUGIN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    PRESENT=1
    # Read Version: header from the plugin main file
    MAIN=$(ls "$d"/really-simple-ssl.php "$d"/rlrsssl-really-simple-ssl.php 2>/dev/null | head -1)
    [ -z "$MAIN" ] && continue
    VER=$(awk -F': *' 'tolower($1) ~ /^[[:space:]]*\**[[:space:]]*version/{gsub(/[ \r]/,"",$2); print $2; exit}' "$MAIN")
    if [ -n "$VER" ] && ver_ge "$VER" "9.1.2"; then
        echo "PASS [PoC]: really-simple-ssl upgraded to $VER in $d."
        SAFE=1
    fi
done

# Alternative: plugin removed entirely → safe
if [ "$PRESENT" = "0" ]; then
    echo "PASS [PoC]: really-simple-ssl plugin removed."
    SAFE=1
fi

[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: vulnerable really-simple-ssl still installed." >&2; exit 1; }

# Regression: WordPress front page must respond
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1/ 2>/dev/null || echo 000)
    case "$CODE" in 200|301|302) echo "PASS [Regression]: WP responds ($CODE)."; exit 0 ;; esac
    sleep 2
done
echo "FAIL [Regression]: WordPress did not respond." >&2
exit 1
