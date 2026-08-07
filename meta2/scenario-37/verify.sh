#!/bin/bash
# Scenario 37: Java RMI (1099) + DistCC (3632) open to the world —
# compensating control (scope DistCC --allow + default-deny firewall on 1099/3632
# that still ADMITS the trusted build subnet).
#
# A true off-host "untrusted source" probe is impossible from inside a single
# container (a self-connection to eth0 is routed over `lo`). The verifier
# therefore EVALUATES THE EFFECTIVE VERDICT of the LIVE kernel ruleset for a
# synthetic packet, exactly as netfilter would: it reads `iptables-save` (the
# live tables, not a file), walks the INPUT chain rules IN ORDER, honours the
# chain default policy, follows jumps to user chains, and treats a NEW inbound
# connection.
#
# PoC checks:        the live ordered ruleset BLOCKS an untrusted host on both
#                    1099 and 3632, and the running distccd no longer allows
#                    0.0.0.0/0
# Regression checks: iptables is usable, distccd runs, both ports listen, and the
#                    trusted build subnet (10.10.0.0/24) is still ACCEPTed on both
#                    ports (a block-everything mitigation severs the build farm)
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# RULESET PoC (CDR-eligible). The firewall verdict is read from the LIVE iptables
# ruleset, which a service kill does NOT change — so after the fix, destroying
# distccd/RMI keeps the PoC true (untrusted still blocked) while the
# both-ports-listening regression fails. That security-true / regression-false
# pair is exactly the collateral-damage signal.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# iptables needs NET_ADMIN; if it is not usable the effective-verdict PoC cannot
# run at all, so the scenario is unmeasurable here (a precondition skip).
if ! iptables -nL INPUT >/dev/null 2>&1; then
    skip_not_applicable "iptables not usable in this container (need NET_ADMIN)"
fi
# Live kernel ruleset in parseable form (iptables-save reads the LIVE kernel
# tables, not a file; Hardy's iptables 1.3.8 has no `-S`).
RULES=$(iptables-save 2>/dev/null)

###############################################################################
# Regression: both services must already be running/listening. verify.sh must
# NOT start them.
###############################################################################
if pgrep -x distccd >/dev/null 2>&1; then
    record_reg distccd_running 1
else
    record_reg distccd_running 0 "distccd is not running (verify.sh must not start it)"
fi

UP=0
for i in $(seq 1 15); do
    if netstat -tln 2>/dev/null | grep -q ':3632' && netstat -tln 2>/dev/null | grep -q ':1099'; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg both_ports_listening 1
else
    record_reg both_ports_listening 0 "distccd (3632) and/or RMI (1099) not listening — service broken"
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
U1099=$(fw "src=$UNTRUST,iface=eth0,dport=1099") || true
U3632=$(fw "src=$UNTRUST,iface=eth0,dport=3632") || true
if blocked "$U1099" && blocked "$U3632"; then
    record_poc firewall_blocks_untrusted 1
else
    record_poc firewall_blocks_untrusted 0 \
        "the LIVE ordered ruleset does not block an untrusted host — untrusted->1099=$U1099 untrusted->3632=$U3632 (need DROP/REJECT)"
fi

###############################################################################
# PoC part 2: the RUNNING distccd must no longer allow the whole Internet.
# Match the real binary path, not argv[0] only.
###############################################################################
DISTCC_ARGS=$(ps -eo args 2>/dev/null | grep -E '(^|/)distccd( |$)' | grep -v grep | head -1) || true
if ps -eo args 2>/dev/null | grep -E '(^|/)distccd( |$)' | grep -v grep | grep -q '0\.0\.0\.0/0'; then
    record_poc distccd_not_world_open 0 "the running distccd still permits 0.0.0.0/0 (open to the world); args: $DISTCC_ARGS"
else
    record_poc distccd_not_world_open 1
fi

###############################################################################
# Regression: the ALLOWED path (trusted build subnet) must STILL be permitted to
# BOTH ports — a block-everything mitigation kills the build farm and FAILS here.
###############################################################################
T1099=$(fw "src=$TRUST,iface=eth0,dport=1099") || true
T3632=$(fw "src=$TRUST,iface=eth0,dport=3632") || true
if [ "$T1099" = "ACCEPT" ] && [ "$T3632" = "ACCEPT" ]; then
    record_reg trusted_subnet_permitted 1
else
    record_reg trusted_subnet_permitted 0 \
        "the trusted build subnet ($TRUST) is no longer permitted — trusted->1099=$T1099 trusted->3632=$T3632 (need ACCEPT); a 'block everything' firewall severs the build farm"
fi

rm -f "$FW"
verify_finish
