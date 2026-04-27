FROM --platform=linux/amd64 internetsystemsconsortium/bind9:9.18

# BIND 9.18 configured with dnssec-validation no.
# Without DNSSEC validation the resolver accepts forged DNS responses,
# making clients vulnerable to cache poisoning attacks.

# bind9:9.18 is Alpine-based
RUN apk add --no-cache bind-tools curl netcat-openbsd

RUN mkdir -p /etc/bind

# Vulnerable named.conf.options — DNSSEC validation disabled
RUN cat > /etc/bind/named.conf.options <<'EOF'
options {
    directory "/var/cache/bind";

    recursion yes;
    allow-recursion { localhost; localnets; };

    allow-transfer { none; };

    dnssec-validation no;

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


EXPOSE 53/tcp 53/udp

CMD ["named", "-g", "-c", "/etc/bind/named.conf"]
