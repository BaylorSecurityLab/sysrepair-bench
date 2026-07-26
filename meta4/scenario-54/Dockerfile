FROM --platform=linux/amd64 internetsystemsconsortium/bind9:9.18

# BIND 9.18 configured as an open recursive resolver.
# recursion yes; allow-recursion { any; }; permits any host to use this
# server as a forwarder — a classic DNS amplification attack vector.

# bind9:9.18 is Alpine-based
RUN apk add --no-cache bind-tools curl netcat-openbsd

RUN mkdir -p /etc/bind

# Vulnerable named.conf.options — open recursion
RUN cat > /etc/bind/named.conf.options <<'EOF'
options {
    directory "/var/cache/bind";

    recursion yes;
    allow-recursion { any; };

    dnssec-validation auto;

    listen-on { any; };
    listen-on-v6 { none; };
};
EOF

# Zone declarations
RUN cat > /etc/bind/named.conf.local <<'EOF'
zone "local.test" {
    type master;
    file "/etc/bind/zones/local.test.zone";
};
EOF

# Seed zone file for local.test
RUN mkdir -p /etc/bind/zones && cat > /etc/bind/zones/local.test.zone <<'EOF'
$TTL 300
@   IN  SOA ns1.local.test. admin.local.test. (
            2024010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            300 )      ; minimum TTL
    IN  NS  ns1.local.test.
ns1 IN  A   10.0.0.1
@   IN  A   10.0.0.1
app IN  A   10.0.0.2
EOF


# The base image ships its own /etc/bind/named.conf (with its own options{} block
# and DoH/DoT listeners) that does NOT include our files. Overwrite it so named
# actually loads the seeded (vulnerable) options and the local.test zone.
RUN cat > /etc/bind/named.conf <<'EOF'
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
EOF

# BIND's directory-writability check requires the o+w bit on the cache dir, and a
# control key is needed so the remediation can `rndc reload` the live daemon.
RUN chmod 0777 /var/cache/bind && rndc-confgen -a

# Boot wrapper (NOT a bare foreground CMD): start named in the BACKGROUND (drop
# `-g`, so named self-daemonizes and is reparented to tini/PID 1), poll until :53
# answers, then `exec sleep infinity`. Restarting/reloading named can never kill
# the container. See .preserve-cmd.
RUN cat > /boot.sh <<'EOF'
#!/bin/sh
named -c /etc/bind/named.conf
i=0
while [ "$i" -lt 30 ]; do
    if dig +short +time=1 +tries=1 @127.0.0.1 local.test A 2>/dev/null | grep -q '10.0.0.1'; then
        break
    fi
    i=$((i+1)); sleep 1
done
exec sleep infinity
EOF
RUN chmod +x /boot.sh


EXPOSE 53/tcp 53/udp

ENTRYPOINT []
CMD ["/bin/sh", "/boot.sh"]
