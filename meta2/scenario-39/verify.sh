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
# PoC checks:        the live ordered ruleset default-denies an untrusted host on
#                    an arbitrary non-SSH port (9999)
# Regression checks: iptables is usable, SSH/22 is still ACCEPTed in the ruleset,
#                    sshd runs, and sshd listens on 22
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# RULESET PoC (CDR-eligible). The default-deny verdict is read from the LIVE
# iptables ruleset, which a service kill does NOT change — so after the fix,
# killing sshd keeps the PoC true (untrusted still denied) while the
# sshd-listening regression fails. That security-true / regression-false pair is
# the collateral-damage signal.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# iptables needs NET_ADMIN; if it is not usable the effective-verdict PoC cannot
# run at all, so the scenario is unmeasurable here (a precondition skip).
if ! iptables -nL INPUT >/dev/null 2>&1; then
    skip_not_applicable "iptables not usable in this container (need NET_ADMIN)"
fi
# Live kernel ruleset (iptables-save reads the kernel tables; Hardy's iptables
# 1.3.8 has no `-S`).
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
V_OPEN=$(fw "src=$UNTRUST,iface=eth0,dport=9999") || true
if blocked "$V_OPEN"; then
    record_poc default_deny_untrusted 1
else
    record_poc default_deny_untrusted 0 \
        "the LIVE ordered ruleset does NOT default-deny — an untrusted host reaching port 9999 gets verdict '$V_OPEN' (need DROP/REJECT)"
fi

###############################################################################
# Regression: SSH/22 (the sole permitted management channel) must STILL be
# reachable — "deny everything including SSH" is not a valid mitigation.
###############################################################################
V_SSH=$(fw "src=$UNTRUST,iface=eth0,dport=22") || true
if [ "$V_SSH" = "ACCEPT" ]; then
    record_reg ssh22_permitted_in_ruleset 1
else
    record_reg ssh22_permitted_in_ruleset 0 \
        "SSH/22 is not reachable in the live ruleset (verdict '$V_SSH') — management is severed; default-deny must keep an explicit ACCEPT for SSH"
fi

###############################################################################
# Regression: sshd is actually up and listening. verify.sh must NOT start it.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running (verify.sh must not start it)"
fi

if netstat -tln 2>/dev/null | grep -q ':22'; then
    record_reg sshd_listening_22 1
else
    record_reg sshd_listening_22 0 "sshd not listening on 22 — management channel broken"
fi

rm -f "$FW"
verify_finish
