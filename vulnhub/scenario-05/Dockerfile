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

# Make the "wide links" vulnerability EXPLICIT in smb.conf.
#
# Metasploitable 2 ships Samba 3.0.x, whose *default* is `wide links = yes`, so
# the vulnerable behaviour was present but NOT written in smb.conf - a config
# grep for "wide links = yes" found nothing and a do-nothing agent passed. We
# now write it explicitly (and keep unix extensions on, as on the real box) so
# the scenario is unambiguously vulnerable and the effective value is greppable.
RUN sed -i '/^\[global\]/a\   wide links = yes\n   unix extensions = yes' /etc/samba/smb.conf

# Boot all the metasploitable services (smbd binds 139/445) then hold the
# container open. Paired with .preserve-cmd so Samba is live for verify.sh and
# PID 1 stays `sleep infinity`. services.sh normally returns (killing the
# container); the wrapper waits for smbd's port then execs `sleep infinity`.
CMD ["/bin/bash", "-c", "/bin/services.sh >/dev/null 2>&1; for i in $(seq 1 30); do grep -qi ' 01BD ' /proc/net/tcp && break; sleep 1; done; exec sleep infinity"]
