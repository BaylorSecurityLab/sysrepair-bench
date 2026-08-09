#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
# Runtime verifier for Terrapin (CVE-2023-48795). It does NOT trust `sshd -T`
# (that only PARSES sshd_config). Instead it opens a raw TCP connection to the
# LIVE sshd, drives the SSH version exchange, and reads the server's KEXINIT
# packet — the authoritative list of algorithms the daemon actually OFFERS.
# python3/openssl/nc are absent on ubuntu:22.04, so it uses bash /dev/tcp + dd.
# It NEVER starts sshd (a dead daemon is a FAIL).
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed Terrapin but killed sshd" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
HOST=127.0.0.1
PORT=22
KEX=/tmp/_kexinit.bin

read_kexinit() {
    # Run the connection in a SUBSHELL: a failed `exec 3<>/dev/tcp/...` is fatal
    # to its shell, so guarding with `|| return 1` in the function body would
    # instead kill the whole verifier on a refused connection. dd bs=1 flushes
    # each byte, so a timeout still leaves the captured prefix (banner + KEXINIT)
    # on disk even though the server never closes the socket.
    ( exec 3<>/dev/tcp/$HOST/$PORT 2>/dev/null || exit 1
      printf 'SSH-2.0-TerrapinVerify\r\n' >&3
      timeout 4 dd bs=1 count=2500 <&3 2>/dev/null
    ) >"$KEX" 2>/dev/null
    [ -s "$KEX" ] && grep -aq 'SSH-2.0' "$KEX"
}

# --- wait for the LIVE daemon (do NOT start it) ---
UP=0
for i in $(seq 1 15); do
    if read_kexinit; then UP=1; break; fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg sshd_answers_kexinit 1 "sshd accepts an SSH handshake on port $PORT"
else
    record_reg sshd_answers_kexinit 0 "sshd not responding on port $PORT (down / not restarted)"
fi

if [ "$UP" = "1" ]; then
    ###########################################################################
    # PoC: the server-offered algorithms must contain no Terrapin-vulnerable modes
    ###########################################################################
    if grep -aq 'chacha20-poly1305' "$KEX"; then
        record_poc no_chacha20_poly1305 0 "sshd still OFFERS chacha20-poly1305 (Terrapin-exploitable)"
    else
        record_poc no_chacha20_poly1305 1
    fi
    if grep -aq 'etm@openssh.com' "$KEX"; then
        record_poc no_etm_macs 0 "sshd still OFFERS Encrypt-then-MAC (EtM) MACs (Terrapin-exploitable)"
    else
        record_poc no_etm_macs 1
    fi
    if grep -aq -- '-cbc' "$KEX"; then
        record_poc no_cbc_ciphers 0 "sshd still OFFERS CBC ciphers (Terrapin-exploitable with EtM)"
    else
        record_poc no_cbc_ciphers 1
    fi
else
    # No KEXINIT was ever read, so the offered-algorithm list is unknown. The
    # PoC checks are recorded as FAILED, never credited: a dead sshd offers
    # nothing, so crediting the empty list would let "killed sshd" read as
    # "Terrapin closed". Every PoC here is behavioural, so they cannot be
    # dropped either -- a summary with zero PoC checks carries no security
    # verdict at all.
    record_poc no_chacha20_poly1305 0 "not demonstrable: sshd sent no KEXINIT (service unreachable)"
    record_poc no_etm_macs 0 "not demonstrable: sshd sent no KEXINIT (service unreachable)"
    record_poc no_cbc_ciphers 0 "not demonstrable: sshd sent no KEXINIT (service unreachable)"
fi

# --- Regression: a real SSH client must still negotiate (config not too strict) ---
if command -v ssh >/dev/null 2>&1; then
    OUT=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=4 \
              -p "$PORT" root@"$HOST" true 2>&1 || true)
    if echo "$OUT" | grep -qi 'unable to negotiate\|no matching'; then
        record_reg ssh_client_negotiates 0 "ssh cannot negotiate with sshd (cipher/MAC set broke it): $OUT"
    else
        record_reg ssh_client_negotiates 1
    fi
else
    echo "  [SKIP] (regression) ssh_client_negotiates: no ssh client in this image"
fi

verify_finish
