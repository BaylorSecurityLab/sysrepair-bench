#!/usr/bin/env bash
# meta4/ad-vm/provision/attacker-baseline.sh
# Installs AD offensive toolchain on Kali rolling; idempotent.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Use a public-only resolver during apt/pip so package installs don't wait on
# the DC's DNS (which may not yet be reachable on first provision). The
# DC-first resolv.conf is written at the end of this script.
cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
EOF

echo "[attacker-baseline] apt update + base packages"
apt-get update -y
# netexec + bloodhound.py ship in Kali's main repo and get built/tested against
# the installed Python, so prefer apt over pip for those two; pip versions on
# fresh Kali occasionally fail with "No matching distribution" when the metadata
# requires a newer Python than the venv resolves.
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap \
    ldap-utils \
    smbclient \
    krb5-user \
    netexec \
    bloodhound.py \
    git curl ca-certificates

echo "[attacker-baseline] pip install impacket + certipy-ad in venv"
if [ ! -d /opt/ad-tools ]; then
    python3 -m venv /opt/ad-tools
fi
/opt/ad-tools/bin/pip install --quiet --upgrade pip
/opt/ad-tools/bin/pip install --quiet impacket certipy-ad

# Symlink the venv bins into /usr/local/bin so scenarios can call them directly.
# netexec + bloodhound-python are installed by apt and already on $PATH as
# `nxc` / `bloodhound-python`, so no symlink needed for those.
for bin in impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump \
           impacket-smbclient impacket-wmiexec impacket-psexec \
           impacket-ntlmrelayx impacket-zerologon_tester \
           certipy-ad; do
    if [ -f "/opt/ad-tools/bin/$bin" ]; then
        ln -sf "/opt/ad-tools/bin/$bin" "/usr/local/bin/$bin"
    fi
done

# Rubeus (Windows binary) — ship via Kerberos.NET/pykerberos? Use Rubeus via .NET isn't native here.
# Use the Python-native alternative for AS-REP/Kerberoast: impacket covers both.

# --- krb5.conf for corp.local ---
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    CORP.LOCAL = {
        kdc = corp-dc01.corp.local
        admin_server = corp-dc01.corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local  = CORP.LOCAL
EOF

# --- scenario mount point + seed creds ---
install -d -m 755 /opt/meta4
install -d -o vagrant -g vagrant -m 755 /home/vagrant/tools
ln -sfn /opt/ad-tools/bin /home/vagrant/tools/bin

# --- final DNS: DC-first for AD tooling (Kerberos, LDAP, SMB) ---
echo "[attacker-baseline] DNS: corp.local via DC"
cat > /etc/resolv.conf <<EOF
search corp.local
nameserver 10.20.30.5
nameserver 1.1.1.1
EOF

cat > /home/vagrant/creds.txt <<'EOF'
# Seed credentials for meta4/ad-vm scenarios
corp\alice:Password1!
EOF
chown vagrant:vagrant /home/vagrant/creds.txt
chmod 600 /home/vagrant/creds.txt

echo "[attacker-baseline] COMPLETE"
