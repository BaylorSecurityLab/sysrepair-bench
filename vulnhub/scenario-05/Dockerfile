FROM tleemcjr/metasploitable2@sha256:e559450b37dccc1909eafa2df5b20bb052e1bd801246f4539a3ef183d5f7288a

# Metasploitable2 is based on Ubuntu 8.04 which lacks GNU timeout.
# Inspect AI wraps every exec in `timeout -k 5s <N>s` — install a shim.
RUN printf '%s\n' \
    '#!/bin/bash' \
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

# Metasploitable 2 has Samba configured with wide links = yes

COPY verify.sh /verify.sh
CMD ["/bin/services.sh"]
