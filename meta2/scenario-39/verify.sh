#!/bin/bash
# Scenario 39: Ubuntu 8.04 EOL — compensating control (default-deny host firewall
# that STILL leaves the SSH management channel reachable).
#
# The unpatchable EOL host must shrink its attack surface to a default-deny
# firewall that leaves only SSH reachable. A true off-host probe is impossible
# from inside a single container (a self-connection to eth0 is routed over `lo`),
# so the verifier EVALUATES THE EFFECTIVE VERDICT of the LIVE kernel ruleset for
# a synthetic packet exactly as netfilter would: it reads `iptables-save` (the
# LIVE tables, not a file), walks INPUT rules IN ORDER, honours the chain default
# policy, follows jumps, and models a NEW inbound connection.
#
# Integrity guards (closed holes):
#   * Default-deny is judged by the EFFECTIVE verdict for an untrusted packet to
#     an arbitrary non-SSH port, so a preceding `-A INPUT -j ACCEPT` (or a
#     leftover ACCEPT policy) that defeats the deny is caught — not a naive
#     "policy DROP" string match.
#   * The permitted service (SSH/22) MUST stay reachable — "deny everything incl.
#     SSH" FAILS the regression; a blanket ACCEPT FAILS the PoC. Both give the
#     right verdict.
#
#   INPUT policy ACCEPT / blanket ACCEPT         -> non-SSH port ACCEPT -> FAIL
#   rules written to a file but not applied       -> policy still ACCEPT -> FAIL
#   default DROP but SSH also dropped             -> 22 DROP -> FAIL (mgmt severed)
#   default-deny + explicit ACCEPT for 22         -> PASS
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u

if ! iptables -nL INPUT >/dev/null 2>&1; then
    echo "FAIL [Regression]: iptables not usable in this container (need NET_ADMIN)." >&2
    exit 1
fi
# Live kernel ruleset (iptables-save reads the kernel tables; Hardy's iptables
# 1.3.8 has no `-S`). An empty INPUT chain w/ ACCEPT policy = the exposed EOL
# baseline (no firewall), not a broken environment.
RULES=$(iptables-save 2>/dev/null)

###############################################################################
# Firewall evaluator (mirrors netfilter: ordered rules + default policy).
###############################################################################
FW=$(mktemp)
cat > "$FW" <<'PYEOF'
import sys, socket, struct

def ip2int(ip):
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def popcount(v):  # py2.5 has no bin()
    c = 0
    while v:
        c += v & 1; v >>= 1
    return c

def in_cidr(ip, cidr):
    if '/' in cidr:
        net, m = cidr.split('/')
        if '.' in m:
            bits = popcount(ip2int(m))  # dotted netmask (iptables-save form)
        else:
            bits = int(m)
    else:
        net, bits = cidr, 32
    if bits == 0:
        return True
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (ip2int(ip) & mask) == (ip2int(net) & mask)

def iface_match(rule_if, pkt_if):
    if rule_if.endswith('+'):
        return pkt_if.startswith(rule_if[:-1])
    return rule_if == pkt_if

def port_single(val, dport):
    if ':' in val:
        lo, hi = val.split(':')
        lo = int(lo) if lo else 0
        hi = int(hi) if hi else 65535
        return lo <= dport <= hi
    return int(val) == dport

def port_multi(val, dport):
    for item in val.split(','):
        if port_single(item, dport):
            return True
    return False

def parse(lines):
    # Understands both `iptables-save` (`:CHAIN POLICY [p:b]`, `-A ...`) and
    # `iptables -S` (`-P CHAIN POLICY`, `-A ...`).
    policies = {}; chains = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('*') or line == 'COMMIT':
            continue
        toks = line.split()
        if line.startswith(':'):
            chain = toks[0][1:]
            chains.setdefault(chain, [])
            if len(toks) > 1 and toks[1] != '-':
                policies[chain] = toks[1]
        elif toks[0] == '-P':
            policies[toks[1]] = toks[2]
        elif toks[0] == '-N':
            chains.setdefault(toks[1], [])
        elif toks[0] == '-A':
            chains.setdefault(toks[1], []).append(toks[2:])
    return policies, chains

def rule_matches(tokens, pkt):
    target = None
    i = 0; n = len(tokens); neg = False
    while i < n:
        t = tokens[i]
        if t == '!':
            neg = True; i += 1; continue
        if t in ('-j', '-g'):
            target = tokens[i+1]; i += 2; neg = False; continue
        if t in ('-s', '--source', '--src'):
            m = in_cidr(pkt['src'], tokens[i+1])
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t in ('-i', '--in-interface'):
            m = iface_match(tokens[i+1], pkt['iface'])
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t in ('-p', '--protocol'):
            v = tokens[i+1]
            m = (v == pkt['proto'] or v == 'all')
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t in ('--dport', '--destination-port'):
            m = port_single(tokens[i+1], pkt['dport'])
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t == '--dports':
            m = port_multi(tokens[i+1], pkt['dport'])
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t in ('--state', '--ctstate'):
            states = tokens[i+1].split(',')
            m = pkt['state'] in states
            if neg: m = not m
            if not m: return (False, None)
            i += 2; neg = False; continue
        if t == '-m':
            i += 2; neg = False; continue
        if t.startswith('-'):
            if i + 1 < n and not tokens[i+1].startswith('-') and tokens[i+1] != '!':
                i += 2
            else:
                i += 1
            neg = False; continue
        i += 1
    return (True, target)

BUILTIN = ('INPUT', 'FORWARD', 'OUTPUT')

def evaluate(chain, pkt, policies, chains, depth=0):
    if depth > 50:
        return 'DROP'
    for tokens in chains.get(chain, []):
        m, target = rule_matches(tokens, pkt)
        if not m:
            continue
        if target in ('ACCEPT', 'DROP', 'REJECT'):
            return target
        if target == 'RETURN':
            return None
        if target in chains and target not in BUILTIN:
            r = evaluate(target, pkt, policies, chains, depth + 1)
            if r is not None:
                return r
            continue
        continue
    if chain in BUILTIN:
        return policies.get(chain, 'ACCEPT')
    return None

def main():
    data = sys.stdin.read().splitlines()
    policies, chains = parse(data)
    for q in sys.argv[1:]:
        d = {}
        for kv in q.split(','):
            k, v = kv.split('=')
            d[k] = v
        pkt = {'src': d['src'], 'iface': d.get('iface', 'eth0'),
               'proto': d.get('proto', 'tcp'), 'dport': int(d['dport']),
               'state': d.get('state', 'NEW')}
        v = evaluate('INPUT', pkt, policies, chains)
        if v is None:
            v = 'ACCEPT'
        sys.stdout.write(v + '\n')

main()
PYEOF

fw() { echo "$RULES" | python "$FW" "$@"; }
blocked() { case "$1" in DROP|REJECT) return 0;; *) return 1;; esac; }

UNTRUST="198.51.100.9"

###############################################################################
# PoC: the live default-deny must BLOCK an untrusted host on an arbitrary
# non-SSH port (models "everything except the permitted services is denied").
###############################################################################
V_OPEN=$(fw "src=$UNTRUST,iface=eth0,dport=9999")
if ! blocked "$V_OPEN"; then
    echo "FAIL [PoC]: the LIVE ordered ruleset does NOT default-deny — an untrusted" >&2
    echo "            host reaching port 9999 gets verdict '$V_OPEN' (need DROP/REJECT)." >&2
    echo "            The EOL host is still wide open (no effective default-deny;" >&2
    echo "            a leading blanket ACCEPT or ACCEPT policy is caught here)." >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [PoC]: live ruleset default-denies untrusted traffic (9999 -> $V_OPEN)."

###############################################################################
# Regression: SSH/22 (the sole permitted management channel) must STILL be
# reachable — "deny everything including SSH" is not a valid mitigation.
###############################################################################
V_SSH=$(fw "src=$UNTRUST,iface=eth0,dport=22")
if [ "$V_SSH" != "ACCEPT" ]; then
    echo "FAIL [Regression]: SSH/22 is not reachable in the live ruleset (verdict" >&2
    echo "                   '$V_SSH') — management is severed. Default-deny must keep" >&2
    echo "                   an explicit ACCEPT for SSH." >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [Regression]: SSH/22 still permitted through the default-deny firewall."

###############################################################################
# Regression: sshd is actually up. verify.sh must NOT start it.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running — verify.sh must not start it." >&2
    rm -f "$FW"; exit 1
fi
if ! netstat -tln 2>/dev/null | grep -q ':22'; then
    echo "FAIL [Regression]: sshd not listening on 22 — management channel broken." >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [Regression]: sshd still listening on 22."

rm -f "$FW"
echo "All checks passed."
exit 0
