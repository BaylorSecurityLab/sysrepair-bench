FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Shared base for meta2 (Ubuntu 8.04 Hardy) scenarios.
#
# Hardy ships coreutils 6.10, which predates the GNU `timeout` binary
# (added in coreutils 7.0, 2008). Inspect AI's sandbox hardcodes
# `timeout -k 5s <N>s <cmd>` around every exec and write_file
# (see inspect_ai/util/_sandbox/docker/docker.py:318), so without this
# shim every sample fails with exit 127 before the agent can run.
#
# The shim handles the subset of GNU timeout flags Inspect actually uses:
#   timeout [-k KILL_AFTER] DURATION CMD [ARGS...]
# durations support s/m/h suffixes; unknown flags are swallowed.

RUN printf '%s\n' \
    '#!/bin/bash' \
    '# Minimal GNU timeout shim. Uses exec so the target command replaces' \
    '# this process — stdout/stderr flow directly to the caller with zero' \
    '# buffering intermediaries. A background watchdog handles the kill.' \
    'k=' \
    'while [ "${1#-}" != "$1" ]; do' \
    '  case $1 in' \
    '    -k) k=$2; shift 2 ;;' \
    '    -k*) k=${1#-k}; shift ;;' \
    '    --kill-after=*) k=${1#--kill-after=}; shift ;;' \
    '    --) shift; break ;;' \
    '    *) shift ;;' \
    '  esac' \
    'done' \
    'p() { case $1 in *s) echo ${1%s};; *m) echo $((${1%m}*60));; *h) echo $((${1%h}*3600));; *) echo $1;; esac; }' \
    'd=$(p "$1"); shift; k=$(p "$k")' \
    '(sleep "$d" 2>/dev/null && kill -TERM $$ 2>/dev/null; [ -n "$k" ] && sleep "$k" 2>/dev/null && kill -KILL $$ 2>/dev/null) &' \
    'exec "$@"' \
    > /usr/local/bin/timeout && chmod +x /usr/local/bin/timeout

# Point every meta2 scenario at old-releases so apt-get works.
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
