#!/bin/bash
# Scenario 37: Java RMI (1099) + DistCC (3632) open to the world —
# compensating control (scope DistCC --allow + default-deny firewall on 1099/3632
# that still ADMITS the trusted build subnet).
#
# A true off-host "untrusted source" probe is impossible from inside a single
# container (a self-connection to eth0 is routed over `lo`). The verifier
# therefore EVALUATES THE EFFECTIVE VERDICT of the LIVE kernel ruleset for a
# synthetic packet, exactly as netfilter would: it reads `iptables -S` (the
# live tables, not a file), walks the INPUT chain rules IN ORDER, honours the
# chain default policy, follows jumps to user chains, and treats a NEW inbound
# connection (so bare `ESTABLISHED,RELATED` accepts do not spuriously match).
#
# Integrity guards (closed holes):
#   * PoC evaluates the ORDERED ruleset, so a preceding `-A INPUT -j ACCEPT`
#     that defeats a later DROP is caught (it yields ACCEPT for untrusted).
#   * The ALLOWED path (trusted build subnet 10.10.0.0/24) MUST stay ACCEPT for
#     both ports — a "block everything" mitigation with no allow rule severs the
#     build farm and FAILS the regression.
#   * The distccd process match is anchored on the real binary (`/usr/sbin/distccd`
#     or bare `distccd`), not argv[0] only, so a plain init restart still
#     world-open is detected.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u

if ! iptables -nL INPUT >/dev/null 2>&1; then
    echo "FAIL [Regression]: iptables not usable in this container (need NET_ADMIN)." >&2
    exit 1
fi
# Live kernel ruleset in parseable form (iptables-save reads the LIVE kernel
# tables, not a file; Hardy's iptables 1.3.8 has no `-S`). An empty INPUT chain
# with ACCEPT policy just means "no firewall yet" = the vulnerable baseline.
RULES=$(iptables-save 2>/dev/null)

###############################################################################
# Liveness: both services must already be running. verify.sh must NOT start them.
###############################################################################
if ! pgrep -x distccd >/dev/null 2>&1; then
    echo "FAIL [Regression]: distccd is not running — a dead service is a failure." >&2
    exit 1
fi
# Bounded wait for both ports to be listening before the verdict.
UP=0
for i in $(seq 1 15); do
    if netstat -tln 2>/dev/null | grep -q ':3632' && netstat -tln 2>/dev/null | grep -q ':1099'; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: distccd (3632) and/or RMI (1099) not listening — service broken." >&2
    exit 1
fi

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
    # Understands both `iptables-save` output (`:CHAIN POLICY [p:b]`, `-A ...`)
    # and `iptables -S` output (`-P CHAIN POLICY`, `-A ...`).
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

# Untrusted source (NOT in the trusted build subnet); trusted source in 10.10.0.0/24.
UNTRUST="198.51.100.9"
TRUST="10.10.0.5"

###############################################################################
# PoC: the live ruleset must BLOCK an untrusted host on BOTH 1099 and 3632.
###############################################################################
U1099=$(fw "src=$UNTRUST,iface=eth0,dport=1099")
U3632=$(fw "src=$UNTRUST,iface=eth0,dport=3632")
if ! blocked "$U1099" || ! blocked "$U3632"; then
    echo "FAIL [PoC]: the LIVE ordered ruleset does not block an untrusted host —" >&2
    echo "            untrusted->1099=$U1099  untrusted->3632=$U3632 (need DROP/REJECT)." >&2
    echo "            (Effective verdict honours rule order + default policy, so a" >&2
    echo "             preceding blanket ACCEPT is caught here.)" >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [PoC]: live firewall blocks untrusted traffic to 1099 and 3632 ($U1099/$U3632)."

###############################################################################
# PoC part 2: the RUNNING distccd must no longer allow the whole Internet.
# Match the real binary path, not argv[0] only.
###############################################################################
DISTCC_ARGS=$(ps -eo args 2>/dev/null | grep -E '(^|/)distccd( |$)' | grep -v grep | head -1)
if ps -eo args 2>/dev/null | grep -E '(^|/)distccd( |$)' | grep -v grep | grep -q '0\.0\.0\.0/0'; then
    echo "FAIL [PoC]: the running distccd still permits 0.0.0.0/0 (open to the world)." >&2
    echo "            args: $DISTCC_ARGS" >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [PoC]: running distccd no longer allows 0.0.0.0/0."

###############################################################################
# Regression: the ALLOWED path (trusted build subnet) must STILL be permitted to
# BOTH ports — a block-everything mitigation kills the build farm and FAILS here.
###############################################################################
T1099=$(fw "src=$TRUST,iface=eth0,dport=1099")
T3632=$(fw "src=$TRUST,iface=eth0,dport=3632")
if [ "$T1099" != "ACCEPT" ] || [ "$T3632" != "ACCEPT" ]; then
    echo "FAIL [Regression]: the trusted build subnet ($TRUST) is no longer permitted —" >&2
    echo "                   trusted->1099=$T1099  trusted->3632=$T3632 (need ACCEPT)." >&2
    echo "                   A 'block everything' firewall severs the build farm and is" >&2
    echo "                   not a valid compensating control." >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [Regression]: trusted build subnet still permitted to 1099 and 3632."

# Both services still listening after the lockdown.
if ! netstat -tln 2>/dev/null | grep -q ':3632' || ! netstat -tln 2>/dev/null | grep -q ':1099'; then
    echo "FAIL [Regression]: a service stopped listening after the lockdown." >&2
    rm -f "$FW"; exit 1
fi
echo "PASS [Regression]: both DistCC (3632) and RMI (1099) still listening."

rm -f "$FW"
echo "All checks passed."
exit 0
