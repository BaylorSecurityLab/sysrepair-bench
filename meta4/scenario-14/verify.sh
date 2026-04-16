#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# GitLab writes its version to /opt/gitlab/version-manifest.txt
VER=$(awk '/^gitlab-ce /{print $2; exit}' /opt/gitlab/version-manifest.txt 2>/dev/null | sed -E 's/^([0-9.]+).*/\1/')
[ -z "$VER" ] && VER=$(cat /opt/gitlab/embedded/service/gitlab-rails/VERSION 2>/dev/null)
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read GitLab version." >&2; exit 1; }

SAFE=0
case "$VER" in
    16.5.*) ver_ge "$VER" "16.5.6" && SAFE=1 ;;
    16.6.*) ver_ge "$VER" "16.6.4" && SAFE=1 ;;
    16.7.*) ver_ge "$VER" "16.7.2" && SAFE=1 ;;
    *) ver_ge "$VER" "16.7.2" && SAFE=1 ;;
esac

if [ "$SAFE" = "1" ]; then
    echo "PASS [PoC]: GitLab upgraded to $VER."
else
    echo "FAIL [PoC]: GitLab $VER vulnerable to CVE-2023-7028." >&2
    exit 1
fi

# GitLab needs several minutes to come up — long retry window
for i in $(seq 1 120); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1/users/sign_in 2>/dev/null || echo 000)
    case "$CODE" in 200|302) echo "PASS [Regression]: GitLab sign_in reachable ($CODE)."; exit 0 ;; esac
    sleep 5
done
echo "FAIL [Regression]: GitLab sign_in did not respond." >&2
exit 1
