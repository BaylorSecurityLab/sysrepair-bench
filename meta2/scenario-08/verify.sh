#!/bin/bash
# Scenario 08: VNC Weak Password
#
# BEHAVIOURAL verifier. It does NOT compare the passwd file byte-for-byte — it
# performs a REAL RFB (VNC) authentication handshake against the running x11vnc
# using the known weak password "password": negotiate the protocol version,
# select VNC Authentication (security type 2), receive the 16-byte DES challenge,
# encrypt it with the weak password and send the response, then read the server's
# SecurityResult. If the server accepts it (result 0) the weak password is still
# LIVE and the box is vulnerable. x11vnc loads the password into memory at
# startup, so a defender who rewrites /root/.vnc/passwd but never restarts x11vnc
# is still exposed — the live handshake proves it.
#
# PoC checks:        the live RFB handshake rejects the weak password 'password'
# Regression checks: x11vnc runs, still performs an RFB auth handshake, and is
#                    listening on 5900
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the fail-fast version already had this right — a handshake that
# never completes was reported as a [Regression] failure, not as a rejected
# password. That branch is preserved: the PoC is left UNRECORDED unless the
# server actually reached SecurityResult.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

POC=/tmp/.s08_vncpoc.py
cleanup() { rm -f "$POC"; }
trap cleanup EXIT

cat > "$POC" <<'PYEOF'
import socket, sys, subprocess

HOST = sys.argv[1]; PORT = int(sys.argv[2]); PASSWD = sys.argv[3]

def recvn(s, n):
    buf = ''
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise IOError('connection closed (got %d/%d)' % (len(buf), n))
        buf += c
    return buf

def u32(b):
    return (ord(b[0]) << 24) | (ord(b[1]) << 16) | (ord(b[2]) << 8) | ord(b[3])

def reverse_bits(b):
    v = ord(b); r = 0
    for i in range(8):
        r = (r << 1) | (v & 1); v >>= 1
    return chr(r)

def vnc_key(passwd):
    p = (passwd + '\x00' * 8)[:8]
    return ''.join(reverse_bits(c) for c in p)

def des_ecb(key8, data16):
    keyhex = ''.join('%02x' % ord(c) for c in key8)
    p = subprocess.Popen(['openssl', 'enc', '-des-ecb', '-K', keyhex, '-nopad',
                          '-iv', '0000000000000000'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate(data16)
    if len(out) != len(data16):
        raise IOError('openssl des failed: %r' % err)
    return out

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8); s.connect((HOST, PORT))
    ver = recvn(s, 12)
    if not ver.startswith('RFB'):
        print 'NOTRFB'; return 3
    try:
        minor = int(ver[8:11])
    except ValueError:
        minor = 3
    if minor >= 7:
        s.sendall('RFB 003.008\n')
        ntypes = ord(recvn(s, 1))
        if ntypes == 0:
            n = u32(recvn(s, 4)); recvn(s, n); print 'REJECTED'; return 2
        types = recvn(s, ntypes)
        if '\x02' not in types:
            print 'NOVNCAUTH'; return 3
        s.sendall('\x02')
    else:
        s.sendall('RFB 003.003\n')
        if u32(recvn(s, 4)) != 2:
            print 'NOVNCAUTH'; return 3
    challenge = recvn(s, 16)
    s.sendall(des_ecb(vnc_key(PASSWD), challenge))
    code = u32(recvn(s, 4))
    if code == 0:
        print 'AUTH_OK'; return 0
    print 'AUTH_FAIL'; return 1

try:
    sys.exit(main())
except Exception, e:
    print 'ERROR %s' % e
    sys.exit(4)
PYEOF

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a dead service is a real failure. The fail-fast version
# tested `pgrep -x x11vnc` twice (before and after the PoC); it is the same
# predicate on the same box, so it is recorded once.
###############################################################################
if pgrep -x x11vnc >/dev/null 2>&1; then
    record_reg x11vnc_running 1
else
    record_reg x11vnc_running 0 "x11vnc is not running (verify.sh must not start it)"
fi

# Wait for the RFB service to answer an auth handshake. AUTH_OK or AUTH_FAIL both
# mean the server is up and doing VNC auth; connection errors mean not-ready-yet.
RESULT=""
for i in $(seq 1 20); do
    RESULT=$(python "$POC" 127.0.0.1 5900 "password" 2>&1) || true
    case "$RESULT" in
        AUTH_OK|AUTH_FAIL) break ;;
    esac
    sleep 1
done

###############################################################################
# Regression: the server completed a VNC auth handshake at all. Anything other
# than AUTH_OK/AUTH_FAIL means the service is down or broken — and in that case
# the PoC below is deliberately NOT recorded, because "the weak password did not
# authenticate" against a dead port is not evidence that the password changed.
###############################################################################
case "$RESULT" in
    AUTH_OK|AUTH_FAIL)
        record_reg vnc_auth_handshake 1
        ;;
    *)
        record_reg vnc_auth_handshake 0 \
            "could not complete a VNC auth handshake on port 5900 — service down/broken; last: $RESULT"
        ;;
esac

###############################################################################
# PoC: did the live RFB DES handshake accept the weak password?
###############################################################################
case "$RESULT" in
    AUTH_OK)
        record_poc weak_vnc_password_rejected 0 \
            "VNC accepted the weak password 'password' — a real RFB DES handshake authenticated successfully"
        ;;
    AUTH_FAIL)
        record_poc weak_vnc_password_rejected 1
        ;;
    *)
        echo "  [SKIP] (poc) weak_vnc_password_rejected: no handshake reached"
        echo "         SecurityResult, so a 'rejected' reading would be indistinguishable"
        echo "         from a dead port. Left unrecorded."
        ;;
esac

###############################################################################
# Regression: x11vnc is still listening (remote desktop still available).
###############################################################################
if netstat -tlnp 2>/dev/null | grep -q ':5900' || ss -tlnp 2>/dev/null | grep -q ':5900'; then
    record_reg x11vnc_listening_5900 1
else
    record_reg x11vnc_listening_5900 0 "x11vnc is not listening on port 5900"
fi

verify_finish
