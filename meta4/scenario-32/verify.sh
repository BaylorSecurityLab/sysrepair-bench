#!/bin/bash
set -u
# Runtime verifier for Terrapin (CVE-2023-48795). It does NOT trust `sshd -T`
# (that only PARSES sshd_config). Instead it opens a raw TCP connection to the
# LIVE sshd, drives the SSH version exchange, and reads the server's KEXINIT
# packet — the authoritative list of algorithms the daemon actually OFFERS.
# python3/openssl/nc are absent on ubuntu:22.04, so it uses bash /dev/tcp + dd.
# It NEVER starts sshd (a dead daemon is a FAIL).
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
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: sshd not responding on port $PORT (down / not restarted)." >&2
    exit 1
fi

# --- PoC: the server-offered algorithms must contain no Terrapin-vulnerable modes ---
FAILED=0
if grep -aq 'chacha20-poly1305' "$KEX"; then
    echo "FAIL [PoC]: sshd still OFFERS chacha20-poly1305 (Terrapin-exploitable)." >&2; FAILED=1
fi
if grep -aq 'etm@openssh.com' "$KEX"; then
    echo "FAIL [PoC]: sshd still OFFERS Encrypt-then-MAC (EtM) MACs (Terrapin-exploitable)." >&2; FAILED=1
fi
if grep -aq -- '-cbc' "$KEX"; then
    echo "FAIL [PoC]: sshd still OFFERS CBC ciphers (Terrapin-exploitable with EtM)." >&2; FAILED=1
fi
[ "$FAILED" = 0 ] || exit 1
echo "PASS [PoC]: live sshd KEXINIT offers no chacha20-poly1305 / CBC / EtM (Terrapin closed)."

# --- Regression: a real SSH client must still negotiate (config not too strict) ---
if command -v ssh >/dev/null 2>&1; then
    OUT=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=4 \
              -p "$PORT" root@"$HOST" true 2>&1 || true)
    if echo "$OUT" | grep -qi 'unable to negotiate\|no matching'; then
        echo "FAIL [Regression]: ssh cannot negotiate with sshd (cipher/MAC set broke it): $OUT" >&2
        exit 1
    fi
fi
echo "PASS [Regression]: sshd accepts an SSH handshake on port $PORT."
exit 0
