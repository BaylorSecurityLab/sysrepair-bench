#!/usr/bin/env python3
"""Generate SysRepair-Bench scenarios 01-10."""
import os

BASE = "/home/abanisenioluwa_oroj1/projects/sys-repair/SysRepair-Bench"

files = {}

# =============================================================================
# SCENARIO 01: SSH permits root login
# =============================================================================
files["scenario-01/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Set a known root password
RUN echo 'root:SysRepairR00t!' | chpasswd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Configure SSH to permit root login (VULNERABLE)
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Ensure password authentication is enabled for testing
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
"""

files["scenario-01/threat.md"] = """# Scenario 01: SSH Permits Root Login

## Vulnerability

The SSH daemon is configured with `PermitRootLogin yes`, allowing direct remote
root login over SSH. This gives attackers who obtain or brute-force the root
password full, unrestricted access to the system without any audit trail
distinguishing which administrator performed an action.

## CWE Classification

**CWE-250: Execution with Unnecessary Privileges**

Allowing direct root login via SSH grants the highest level of system privileges
to any authenticated session. Normal administrative workflows should use
unprivileged accounts with `sudo` for privilege escalation, providing
accountability and limiting the blast radius of compromised credentials.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PermitRootLogin yes`
- **Service**: OpenSSH Server (sshd)

## Expected Remediation

The `PermitRootLogin` directive should be set to `no` (or `prohibit-password`
at minimum). The SSH service must be restarted after the configuration change.
Normal user SSH access must remain functional.

## References

- TAMU ssh.sh - disables root login
- UTSA script.sh - disables root login
- CIS Benchmark for Ubuntu - 5.2.10 Ensure SSH root login is disabled
"""

files["scenario-01/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 01 - Verification Script
# SSH Permits Root Login (CWE-250)
#
# PoC Test:        Verify root login via SSH is denied
# Regression Test: Verify SSH is running and normal users can still connect
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 01: SSH Permits Root Login"
echo "========================================"

###############################################################################
# PoC Test: Attempt SSH root login - should be DENIED after remediation
###############################################################################
echo ""
echo "[PoC Test] Checking PermitRootLogin configuration..."

# Check configuration via sshd -T (effective config)
ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
echo "  PermitRootLogin is set to: ${ROOT_LOGIN:-unknown}"

if echo "$ROOT_LOGIN" | grep -qi "^yes$"; then
    echo "  [FAIL] PermitRootLogin is still 'yes' - root login is permitted"
    exit $FAIL
fi

echo "  [PASS] PermitRootLogin is not 'yes'"

# Also try actual SSH connection as root to confirm
echo ""
echo "[PoC Test] Attempting actual SSH login as root..."

if sshpass -p 'SysRepairR00t!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 root@127.0.0.1 "echo root_access_granted" 2>/dev/null; then
    echo "  [FAIL] Root SSH login succeeded - vulnerability still present"
    exit $FAIL
fi

echo "  [PASS] Root SSH login is denied"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

# Check SSH is listening on port 22
if ! ss -tlnp 2>/dev/null | grep -q ':22\b'; then
    echo "  [FAIL] SSH is not listening on port 22"
    exit $FAIL
fi
echo "  [PASS] SSH is listening on port 22"

###############################################################################
# Regression Test: Normal user SSH login must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login as normal user (testuser)..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] Normal user SSH login failed - SSH service is broken"
    exit $FAIL
fi
echo "  [PASS] Normal user SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 02: SSH allows empty passwords
# =============================================================================
files["scenario-02/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server and utilities
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a user with an empty password (VULNERABLE)
RUN useradd -m -s /bin/bash emptyuser && \
    passwd -d emptyuser

# Create a normal user with a real password for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Configure SSH to allow empty passwords (VULNERABLE)
RUN sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config && \
    grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
"""

files["scenario-02/threat.md"] = """# Scenario 02: SSH Allows Empty Passwords

## Vulnerability

The SSH daemon is configured with `PermitEmptyPasswords yes`, allowing users
with empty (blank) passwords to authenticate over SSH. Combined with user
accounts that have no password set, this allows unauthenticated remote access
to the system.

## CWE Classification

**CWE-258: Empty Password in Configuration File**

The SSH configuration explicitly permits authentication with empty passwords,
which is functionally equivalent to no authentication at all for affected
accounts. Any user account with a blank password becomes remotely accessible
without credentials.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PermitEmptyPasswords yes`
- **Service**: OpenSSH Server (sshd)
- **Affected User**: `emptyuser` (has empty password)

## Expected Remediation

Set `PermitEmptyPasswords no` in `/etc/ssh/sshd_config` and restart the SSH
service. Optionally, also set a password on the `emptyuser` account or lock it.
Normal user SSH access with real passwords must remain functional.

## References

- TAMU ssh.sh - disables empty passwords
- UTSA script.sh - disables empty passwords
- CIS Benchmark for Ubuntu - 5.2.11 Ensure SSH PermitEmptyPasswords is disabled
"""

files["scenario-02/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 02 - Verification Script
# SSH Allows Empty Passwords (CWE-258)
#
# PoC Test:        Verify empty-password SSH login is denied
# Regression Test: Verify SSH works with real passwords
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 02: SSH Allows Empty Passwords"
echo "========================================"

###############################################################################
# PoC Test: Check configuration for PermitEmptyPasswords
###############################################################################
echo ""
echo "[PoC Test] Checking PermitEmptyPasswords configuration..."

EMPTY_PW=$(sshd -T 2>/dev/null | grep -i "^permitemptypasswords" | awk '{print $2}')
echo "  PermitEmptyPasswords is set to: ${EMPTY_PW:-unknown}"

if echo "$EMPTY_PW" | grep -qi "^yes$"; then
    echo "  [FAIL] PermitEmptyPasswords is still 'yes'"
    exit $FAIL
fi

echo "  [PASS] PermitEmptyPasswords is not 'yes'"

###############################################################################
# PoC Test: Attempt SSH login with empty password
###############################################################################
echo ""
echo "[PoC Test] Attempting SSH login with empty password (emptyuser)..."

# Try to SSH with an empty password
RESULT=$(sshpass -p '' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 emptyuser@127.0.0.1 "echo empty_access_granted" 2>/dev/null || true)

if [ "$RESULT" = "empty_access_granted" ]; then
    echo "  [FAIL] Empty password SSH login succeeded - vulnerability still present"
    exit $FAIL
fi

echo "  [PASS] Empty password SSH login is denied"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: Normal user with real password must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login with real password (testuser)..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] Normal user SSH login failed - SSH service is broken"
    exit $FAIL
fi
echo "  [PASS] Normal user SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 03: SSH weak ciphers configured
# =============================================================================
files["scenario-03/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configure weak ciphers (VULNERABLE)
# Includes deprecated 3des-cbc and the strong aes ciphers
RUN echo "Ciphers 3des-cbc,aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
"""

files["scenario-03/threat.md"] = """# Scenario 03: SSH Weak Ciphers Configured

## Vulnerability

The SSH daemon is configured to accept weak and deprecated cryptographic
ciphers including `3des-cbc` and `aes128-cbc`. These ciphers are vulnerable
to known cryptographic attacks (e.g., SWEET32 for 3DES, padding oracle
attacks for CBC-mode ciphers) and should not be used.

## CWE Classification

**CWE-327: Use of a Broken or Risky Cryptographic Algorithm**

The SSH configuration includes cryptographic ciphers that are known to be
weak or broken. An attacker performing a man-in-the-middle attack could
potentially decrypt SSH traffic if weak ciphers are negotiated.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `Ciphers 3des-cbc,aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr`
- **Service**: OpenSSH Server (sshd)
- **Weak Ciphers**: `3des-cbc`, `aes128-cbc`

## Expected Remediation

Remove weak ciphers from the `Ciphers` directive. Acceptable ciphers include
only CTR or GCM mode ciphers:
`Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com`

The SSH service must be restarted and must still accept connections using
strong ciphers.

## References

- UTSA script.sh line 43 (Ciphers aes128-ctr,aes192-ctr,aes256-ctr)
- CIS Benchmark for Ubuntu - 5.2.13 Ensure only strong ciphers are used
- NIST SP 800-52 Rev 2
"""

files["scenario-03/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 03 - Verification Script
# SSH Weak Ciphers Configured (CWE-327)
#
# PoC Test:        Verify weak ciphers (3des-cbc, aes128-cbc) are not offered
# Regression Test: Verify SSH still works with strong ciphers
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 03: SSH Weak Ciphers"
echo "========================================"

# List of weak ciphers to check for
WEAK_CIPHERS="3des-cbc aes128-cbc aes192-cbc aes256-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc"

###############################################################################
# PoC Test: Check that no weak ciphers are configured
###############################################################################
echo ""
echo "[PoC Test] Checking for weak ciphers in sshd configuration..."

CONFIGURED_CIPHERS=$(sshd -T 2>/dev/null | grep -i "^ciphers" | awk '{print $2}')
echo "  Configured ciphers: ${CONFIGURED_CIPHERS:-default}"

FOUND_WEAK=0
for cipher in $WEAK_CIPHERS; do
    if echo "$CONFIGURED_CIPHERS" | grep -qi "$cipher"; then
        echo "  [FAIL] Weak cipher found: $cipher"
        FOUND_WEAK=1
    fi
done

if [ $FOUND_WEAK -eq 1 ]; then
    echo "  [FAIL] Weak ciphers are still configured"
    exit $FAIL
fi

echo "  [PASS] No weak ciphers found in configuration"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: SSH must work with strong ciphers
###############################################################################
echo ""
echo "[Regression Test] Testing SSH connection with strong cipher (aes256-ctr)..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -c aes256-ctr \
    -p 22 testuser@127.0.0.1 "echo cipher_test_passed" 2>/dev/null || true)

if [ "$RESULT" != "cipher_test_passed" ]; then
    echo "  [FAIL] SSH connection with strong cipher failed"
    exit $FAIL
fi
echo "  [PASS] SSH works with strong ciphers"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 04: SSH X11 forwarding enabled + high MaxAuthTries
# =============================================================================
files["scenario-04/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Enable X11 forwarding (VULNERABLE)
RUN sed -i 's/^#*X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config && \
    grep -q '^X11Forwarding' /etc/ssh/sshd_config || echo "X11Forwarding yes" >> /etc/ssh/sshd_config

# Set high MaxAuthTries (VULNERABLE - allows brute force)
RUN sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 30/' /etc/ssh/sshd_config && \
    grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo "MaxAuthTries 30" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
"""

files["scenario-04/threat.md"] = """# Scenario 04: SSH X11 Forwarding Enabled + High MaxAuthTries

## Vulnerability

Two SSH misconfigurations are present:

1. **X11 Forwarding Enabled**: `X11Forwarding yes` allows forwarding of X11
   graphical display connections through SSH. This exposes the server to X11
   security vulnerabilities and can be used as an attack vector if the X11
   client or server has vulnerabilities.

2. **High MaxAuthTries**: `MaxAuthTries 30` allows up to 30 authentication
   attempts per connection, greatly facilitating brute-force password attacks.
   The recommended maximum is 4-6 attempts.

## CWE Classification

**CWE-307: Improper Restriction of Excessive Authentication Attempts**

The high `MaxAuthTries` value allows an attacker to make many password guesses
per SSH connection, significantly reducing the time needed for a brute-force
attack. Combined with the unnecessary X11 forwarding, this represents an
inadequately hardened SSH configuration.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Settings**:
  - `X11Forwarding yes`
  - `MaxAuthTries 30`
- **Service**: OpenSSH Server (sshd)

## Expected Remediation

- Set `X11Forwarding no`
- Set `MaxAuthTries` to 4 (or at most 6)
- Restart the SSH service
- Normal SSH access must remain functional

## References

- UTSA script.sh - disables X11 forwarding, sets MaxAuthTries to 4
- CIS Benchmark for Ubuntu - 5.2.6 Ensure SSH X11 forwarding is disabled
- CIS Benchmark for Ubuntu - 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less
"""

files["scenario-04/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 04 - Verification Script
# SSH X11 Forwarding + High MaxAuthTries (CWE-307)
#
# PoC Test:        Verify X11Forwarding is off, MaxAuthTries <= 6
# Regression Test: Verify SSH still works normally
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 04: X11 Forwarding + MaxAuthTries"
echo "========================================"

###############################################################################
# PoC Test: Check X11Forwarding
###############################################################################
echo ""
echo "[PoC Test] Checking X11Forwarding configuration..."

X11FWD=$(sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print $2}')
echo "  X11Forwarding is set to: ${X11FWD:-unknown}"

if echo "$X11FWD" | grep -qi "^yes$"; then
    echo "  [FAIL] X11Forwarding is still enabled"
    exit $FAIL
fi

echo "  [PASS] X11Forwarding is disabled"

###############################################################################
# PoC Test: Check MaxAuthTries
###############################################################################
echo ""
echo "[PoC Test] Checking MaxAuthTries configuration..."

MAX_AUTH=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}')
echo "  MaxAuthTries is set to: ${MAX_AUTH:-unknown}"

if [ -z "$MAX_AUTH" ]; then
    echo "  [FAIL] Could not determine MaxAuthTries"
    exit $FAIL
fi

if [ "$MAX_AUTH" -gt 6 ]; then
    echo "  [FAIL] MaxAuthTries is $MAX_AUTH (should be 6 or less)"
    exit $FAIL
fi

echo "  [PASS] MaxAuthTries is $MAX_AUTH (acceptable: <= 6)"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: SSH connection must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login as testuser..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] SSH login failed - service is broken"
    exit $FAIL
fi
echo "  [PASS] SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 05: SSH password-only auth, no key restriction
# =============================================================================
files["scenario-05/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Disable public key authentication (VULNERABLE - forces password-only)
RUN sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config && \
    grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo "PubkeyAuthentication no" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Pre-generate an SSH keypair for the testuser (for regression testing)
RUN mkdir -p /home/testuser/.ssh && \
    ssh-keygen -t ed25519 -f /home/testuser/.ssh/id_ed25519 -N '' -q && \
    cat /home/testuser/.ssh/id_ed25519.pub >> /home/testuser/.ssh/authorized_keys && \
    chmod 700 /home/testuser/.ssh && \
    chmod 600 /home/testuser/.ssh/authorized_keys /home/testuser/.ssh/id_ed25519 && \
    chown -R testuser:testuser /home/testuser/.ssh

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
"""

files["scenario-05/threat.md"] = """# Scenario 05: SSH Password-Only Auth, No Key Restriction

## Vulnerability

The SSH daemon has `PubkeyAuthentication no`, which disables SSH key-based
authentication entirely. This forces all users to authenticate with passwords
only, eliminating the strongest form of SSH authentication and making the
system vulnerable to password brute-force attacks.

## CWE Classification

**CWE-308: Use of Single-factor Authentication**

By disabling public key authentication, the system relies solely on password-
based authentication (a single factor: something you know). SSH keys provide
a much stronger authentication mechanism (something you have) and should
always be enabled as an authentication option.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PubkeyAuthentication no`
- **Service**: OpenSSH Server (sshd)

## Expected Remediation

Set `PubkeyAuthentication yes` in `/etc/ssh/sshd_config` and restart the SSH
service. Key-based authentication should work after the fix. An SSH keypair
and authorized_keys file are already configured for `testuser`.

## References

- TAMU ssh.sh - generates and deploys SSH keys, enables pubkey auth
- CIS Benchmark for Ubuntu - 5.2.12 Ensure SSH PubkeyAuthentication is enabled
"""

files["scenario-05/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 05 - Verification Script
# SSH Password-Only Auth (CWE-308)
#
# PoC Test:        Verify PubkeyAuthentication is enabled
# Regression Test: Verify SSH key-based login works
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 05: SSH Password-Only Auth"
echo "========================================"

###############################################################################
# PoC Test: Check PubkeyAuthentication setting
###############################################################################
echo ""
echo "[PoC Test] Checking PubkeyAuthentication configuration..."

PUBKEY_AUTH=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}')
echo "  PubkeyAuthentication is set to: ${PUBKEY_AUTH:-unknown}"

if echo "$PUBKEY_AUTH" | grep -qi "^no$"; then
    echo "  [FAIL] PubkeyAuthentication is still disabled"
    exit $FAIL
fi

echo "  [PASS] PubkeyAuthentication is enabled"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: SSH key-based login must work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH key-based login as testuser..."

RESULT=$(ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -o PasswordAuthentication=no \
    -i /home/testuser/.ssh/id_ed25519 \
    -p 22 testuser@127.0.0.1 "echo key_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "key_access_granted" ]; then
    echo "  [FAIL] SSH key-based login failed"
    exit $FAIL
fi
echo "  [PASS] SSH key-based login works correctly"

###############################################################################
# Regression Test: Password login should also still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH password login as testuser..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo password_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "password_access_granted" ]; then
    echo "  [WARN] Password login failed (may be acceptable if only keys are required)"
else
    echo "  [PASS] SSH password login also works"
fi

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 06: Apache ServerTokens Full / ServerSignature On
# =============================================================================
files["scenario-06/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache2
RUN apt-get update && \
    apt-get install -y apache2 curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a test page
RUN echo "<html><body><h1>SysRepair Test Page</h1><p>Apache is working.</p></body></html>" > /var/www/html/index.html

# Configure Apache to expose full version info (VULNERABLE)
RUN echo "ServerTokens Full" >> /etc/apache2/conf-enabled/security.conf && \
    echo "ServerSignature On" >> /etc/apache2/conf-enabled/security.conf

# If security.conf doesn't exist, create it
RUN if [ ! -f /etc/apache2/conf-enabled/security.conf ]; then \
        echo "ServerTokens Full" > /etc/apache2/conf-available/security.conf && \
        echo "ServerSignature On" >> /etc/apache2/conf-available/security.conf && \
        a2enconf security; \
    fi

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
"""

files["scenario-06/threat.md"] = """# Scenario 06: Apache ServerTokens Full / ServerSignature On

## Vulnerability

Apache is configured with `ServerTokens Full` and `ServerSignature On`, which
causes the server to disclose its full version string, OS information, and
module versions in HTTP response headers and error pages. This information
helps attackers identify specific vulnerabilities for the running version.

## CWE Classification

**CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**

The web server reveals detailed version and platform information in HTTP
headers (`Server: Apache/2.x.xx (Ubuntu) ...`) and in auto-generated error
pages. This information disclosure aids attackers in fingerprinting the
server and selecting appropriate exploits.

## Affected Configuration

- **File**: `/etc/apache2/conf-enabled/security.conf` (or `/etc/apache2/apache2.conf`)
- **Settings**:
  - `ServerTokens Full` (should be `Prod`)
  - `ServerSignature On` (should be `Off`)
- **Service**: Apache HTTP Server

## Expected Remediation

- Set `ServerTokens Prod` (only shows "Apache" without version)
- Set `ServerSignature Off` (no server info on error pages)
- Restart Apache
- Apache must still serve web pages correctly

## References

- TAMU apache.sh - sets ServerTokens Prod, ServerSignature Off
- UTSA script.sh - sets ServerTokens Prod, ServerSignature Off
- CIS Benchmark for Apache - 3.3 Ensure ServerTokens is set to Prod
"""

files["scenario-06/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 06 - Verification Script
# Apache ServerTokens Full / ServerSignature On (CWE-200)
#
# PoC Test:        Verify Server header doesn't expose version details
# Regression Test: Verify Apache still serves pages
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

echo "========================================"
echo " Scenario 06: Apache Version Disclosure"
echo "========================================"

# Wait for Apache to start
sleep 2

###############################################################################
# PoC Test: Check Server header for version info
###############################################################################
echo ""
echo "[PoC Test] Checking HTTP Server header for version disclosure..."

HEADERS=$(curl -sI http://127.0.0.1/ 2>/dev/null)
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" || true)
echo "  Server header: ${SERVER_HEADER:-not found}"

# Check if the Server header contains version numbers (e.g., Apache/2.4.xx)
if echo "$SERVER_HEADER" | grep -qiE "Apache/[0-9]"; then
    echo "  [FAIL] Server header exposes Apache version number"
    exit $FAIL
fi

echo "  [PASS] Server header does not expose version number"

###############################################################################
# PoC Test: Check for ServerSignature in error pages
###############################################################################
echo ""
echo "[PoC Test] Checking error pages for server signature..."

ERROR_PAGE=$(curl -s http://127.0.0.1/nonexistent_page_12345 2>/dev/null)

if echo "$ERROR_PAGE" | grep -qiE "Apache/[0-9]"; then
    echo "  [FAIL] Error page exposes Apache version information"
    exit $FAIL
fi

echo "  [PASS] Error pages do not expose version information"

###############################################################################
# Regression Test: Apache must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking Apache is running..."

if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "  [FAIL] Apache process is not running"
    exit $FAIL
fi
echo "  [PASS] Apache process is running"

###############################################################################
# Regression Test: Apache must serve pages
###############################################################################
echo ""
echo "[Regression Test] Checking Apache serves content..."

HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
echo "  HTTP response code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Apache is not serving pages (HTTP $HTTP_CODE)"
    exit $FAIL
fi

CONTENT=$(curl -s http://127.0.0.1/ 2>/dev/null)
if ! echo "$CONTENT" | grep -q "SysRepair Test Page"; then
    echo "  [FAIL] Apache served unexpected content"
    exit $FAIL
fi
echo "  [PASS] Apache serves pages correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 07: Apache directory listing enabled
# =============================================================================
files["scenario-07/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache2
RUN apt-get update && \
    apt-get install -y apache2 curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create test files (but no index.html in the test directory)
RUN echo "<html><body><h1>Main Page</h1></body></html>" > /var/www/html/index.html
RUN mkdir -p /var/www/html/files && \
    echo "secret data 1" > /var/www/html/files/config.txt && \
    echo "secret data 2" > /var/www/html/files/database.sql && \
    echo "secret data 3" > /var/www/html/files/backup.tar.gz

# Enable directory listing (VULNERABLE)
RUN sed -i 's/Options -Indexes/Options +Indexes/' /etc/apache2/conf-available/security.conf 2>/dev/null; \
    sed -i 's/Options -Indexes/Options +Indexes/' /etc/apache2/apache2.conf 2>/dev/null; \
    # Also ensure the directory config allows Indexes
    if grep -q '<Directory /var/www/>' /etc/apache2/apache2.conf; then \
        sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/Options .*/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf; \
    fi

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
"""

files["scenario-07/threat.md"] = """# Scenario 07: Apache Directory Listing Enabled

## Vulnerability

Apache is configured with `Options +Indexes`, which enables automatic directory
listings when no index file (e.g., `index.html`) is present in a directory.
This allows attackers to browse the contents of directories on the web server,
potentially discovering sensitive files such as configuration files, backups,
database dumps, and other artifacts.

## CWE Classification

**CWE-548: Exposure of Information Through Directory Listing**

When directory indexing is enabled, the web server automatically generates an
HTML page listing all files in a directory when no index file exists. This
can expose sensitive files, internal application structure, and temporary
files to unauthorized users.

## Affected Configuration

- **File**: `/etc/apache2/apache2.conf` and/or `/etc/apache2/conf-available/security.conf`
- **Setting**: `Options +Indexes` or `Options Indexes FollowSymLinks`
- **Service**: Apache HTTP Server
- **Exposed Directory**: `/var/www/html/files/`

## Expected Remediation

- Replace `Options Indexes` with `Options -Indexes` in all relevant config files
- Alternatively, set `Options None` or remove `Indexes` from `Options`
- Restart Apache
- Apache must still serve static files directly (by exact URL) and the main page

## References

- TAMU apache.sh - disables directory listing
- CIS Benchmark for Apache - 3.4 Ensure Options -Indexes is set
"""

files["scenario-07/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 07 - Verification Script
# Apache Directory Listing Enabled (CWE-548)
#
# PoC Test:        Verify directory listing is disabled
# Regression Test: Verify Apache serves static files and main page
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

echo "========================================"
echo " Scenario 07: Apache Directory Listing"
echo "========================================"

# Wait for Apache to start
sleep 2

###############################################################################
# PoC Test: Check if directory listing is visible
###############################################################################
echo ""
echo "[PoC Test] Checking for directory listing at /files/..."

DIR_RESPONSE=$(curl -s http://127.0.0.1/files/ 2>/dev/null)
HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/files/ 2>/dev/null)
echo "  HTTP response code for /files/: $HTTP_CODE"

if echo "$DIR_RESPONSE" | grep -qi "Index of"; then
    echo "  [FAIL] Directory listing is visible - shows 'Index of'"
    exit $FAIL
fi

# Also check if individual filenames are exposed
if echo "$DIR_RESPONSE" | grep -qi "config.txt\|database.sql\|backup.tar.gz"; then
    echo "  [FAIL] Directory listing exposes file names"
    exit $FAIL
fi

echo "  [PASS] Directory listing is not visible"

###############################################################################
# Regression Test: Apache must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking Apache is running..."

if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "  [FAIL] Apache process is not running"
    exit $FAIL
fi
echo "  [PASS] Apache process is running"

###############################################################################
# Regression Test: Main page must still be served
###############################################################################
echo ""
echo "[Regression Test] Checking main page is served..."

HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Main page not served (HTTP $HTTP_CODE)"
    exit $FAIL
fi
echo "  [PASS] Main page served (HTTP 200)"

###############################################################################
# Regression Test: Direct file access must still work
###############################################################################
echo ""
echo "[Regression Test] Checking direct file access works..."

CONTENT=$(curl -s http://127.0.0.1/files/config.txt 2>/dev/null)
HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/files/config.txt 2>/dev/null)

if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Direct file access failed (HTTP $HTTP_CODE)"
    exit $FAIL
fi

if ! echo "$CONTENT" | grep -q "secret data 1"; then
    echo "  [FAIL] File content is incorrect"
    exit $FAIL
fi
echo "  [PASS] Direct file access works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 08: Apache TRACE method enabled
# =============================================================================
files["scenario-08/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache2
RUN apt-get update && \
    apt-get install -y apache2 curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a test page
RUN echo "<html><body><h1>SysRepair Test Page</h1><p>Apache is working.</p></body></html>" > /var/www/html/index.html

# Enable TRACE method (VULNERABLE)
# TraceEnable is On by default in Apache, but we make it explicit
RUN echo "TraceEnable On" >> /etc/apache2/apache2.conf

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
"""

files["scenario-08/threat.md"] = """# Scenario 08: Apache TRACE Method Enabled

## Vulnerability

The Apache HTTP server has `TraceEnable On`, which allows the HTTP TRACE
method. The TRACE method echoes back the received request, including any
headers. This can be exploited in Cross-Site Tracing (XST) attacks to steal
credentials, session tokens, and other sensitive information from HTTP
headers, particularly cookies marked as HttpOnly.

## CWE Classification

**CWE-693: Protection Mechanism Failure**

The TRACE method defeats the protection provided by the HttpOnly cookie flag.
HttpOnly is designed to prevent JavaScript from accessing cookies, but TRACE
reflects cookies back in the response body where JavaScript can read them.
This is a failure of the HttpOnly protection mechanism.

## Affected Configuration

- **File**: `/etc/apache2/apache2.conf`
- **Setting**: `TraceEnable On`
- **Service**: Apache HTTP Server

## Expected Remediation

- Set `TraceEnable Off` in the Apache configuration
- Restart Apache
- GET, POST, and other standard methods must still work

## References

- UTSA script.sh - sets TraceEnable Off
- CIS Benchmark for Apache - 3.8 Ensure the TRACE method is disabled
- OWASP - Cross-Site Tracing (XST)
"""

files["scenario-08/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 08 - Verification Script
# Apache TRACE Method Enabled (CWE-693)
#
# PoC Test:        Verify TRACE requests are rejected
# Regression Test: Verify GET requests still work
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

echo "========================================"
echo " Scenario 08: Apache TRACE Method"
echo "========================================"

# Wait for Apache to start
sleep 2

###############################################################################
# PoC Test: Send TRACE request
###############################################################################
echo ""
echo "[PoC Test] Sending HTTP TRACE request..."

TRACE_CODE=$(curl -so /dev/null -w '%{http_code}' -X TRACE http://127.0.0.1/ 2>/dev/null)
echo "  TRACE response code: $TRACE_CODE"

TRACE_BODY=$(curl -s -X TRACE http://127.0.0.1/ 2>/dev/null)

# TRACE should be rejected (405 Method Not Allowed or 403 Forbidden)
# A successful TRACE returns 200 and echoes the request
if [ "$TRACE_CODE" = "200" ]; then
    echo "  [FAIL] TRACE method returned 200 OK - method is enabled"
    echo "  Response body: $TRACE_BODY"
    exit $FAIL
fi

# Also check if the response echoes back the request (characteristic of TRACE)
if echo "$TRACE_BODY" | grep -qi "TRACE / HTTP"; then
    echo "  [FAIL] TRACE method echoes back the request"
    exit $FAIL
fi

echo "  [PASS] TRACE method is disabled (HTTP $TRACE_CODE)"

###############################################################################
# Regression Test: Apache must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking Apache is running..."

if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "  [FAIL] Apache process is not running"
    exit $FAIL
fi
echo "  [PASS] Apache process is running"

###############################################################################
# Regression Test: GET requests must still work
###############################################################################
echo ""
echo "[Regression Test] Checking GET request works..."

HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
echo "  GET response code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] GET request failed (HTTP $HTTP_CODE)"
    exit $FAIL
fi

CONTENT=$(curl -s http://127.0.0.1/ 2>/dev/null)
if ! echo "$CONTENT" | grep -q "SysRepair Test Page"; then
    echo "  [FAIL] GET returned unexpected content"
    exit $FAIL
fi
echo "  [PASS] GET request works correctly"

###############################################################################
# Regression Test: POST requests should also work
###############################################################################
echo ""
echo "[Regression Test] Checking POST request works..."

POST_CODE=$(curl -so /dev/null -w '%{http_code}' -X POST -d "test=data" http://127.0.0.1/ 2>/dev/null)
echo "  POST response code: $POST_CODE"

# POST to a static page typically returns 200 or 405, but not an error
if [ "$POST_CODE" = "500" ] || [ "$POST_CODE" = "503" ]; then
    echo "  [FAIL] POST request caused server error (HTTP $POST_CODE)"
    exit $FAIL
fi
echo "  [PASS] POST request handled without server error"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 09: Nginx version disclosure
# =============================================================================
files["scenario-09/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install nginx
RUN apt-get update && \
    apt-get install -y nginx curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a test page
RUN echo "<html><body><h1>SysRepair Test Page</h1><p>Nginx is working.</p></body></html>" > /var/www/html/index.html

# Ensure server_tokens is on (VULNERABLE - this is the default, but make explicit)
RUN sed -i '/http {/a\    server_tokens on;' /etc/nginx/nginx.conf 2>/dev/null || \
    echo "server_tokens on;" >> /etc/nginx/conf.d/default.conf 2>/dev/null || true

# Remove the default site config if it conflicts and create a clean one
RUN rm -f /etc/nginx/sites-enabled/default 2>/dev/null; \
    echo 'server { \
    listen 80 default_server; \
    listen [::]:80 default_server; \
    root /var/www/html; \
    index index.html; \
    server_name _; \
    location / { \
        try_files $uri $uri/ =404; \
    } \
}' > /etc/nginx/sites-enabled/default

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
"""

files["scenario-09/threat.md"] = """# Scenario 09: Nginx Version Disclosure

## Vulnerability

Nginx is configured with `server_tokens on` (the default), which causes the
server to include its version number in HTTP response headers
(`Server: nginx/1.x.x`) and on default error pages. This information helps
attackers identify the exact nginx version and find known vulnerabilities.

## CWE Classification

**CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**

The web server reveals its version number in the `Server` HTTP header and on
auto-generated error pages. This information disclosure aids attackers in
fingerprinting the server and selecting version-specific exploits.

## Affected Configuration

- **File**: `/etc/nginx/nginx.conf`
- **Setting**: `server_tokens on` (inside `http` block)
- **Service**: Nginx

## Expected Remediation

- Set `server_tokens off;` in the `http` block of `/etc/nginx/nginx.conf`
- Reload or restart nginx
- Nginx must still serve web pages correctly

## References

- TAMU harden_nginx.sh - sets server_tokens off
- CIS Benchmark for Nginx - Ensure server_tokens directive is set to off
"""

files["scenario-09/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 09 - Verification Script
# Nginx Version Disclosure (CWE-200)
#
# PoC Test:        Verify Server header doesn't expose nginx version
# Regression Test: Verify nginx still serves pages
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

echo "========================================"
echo " Scenario 09: Nginx Version Disclosure"
echo "========================================"

# Wait for nginx to start
sleep 2

###############################################################################
# PoC Test: Check Server header for version info
###############################################################################
echo ""
echo "[PoC Test] Checking HTTP Server header for version disclosure..."

HEADERS=$(curl -sI http://127.0.0.1/ 2>/dev/null)
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" || true)
echo "  Server header: ${SERVER_HEADER:-not found}"

# Check if the Server header contains version numbers (e.g., nginx/1.24.0)
if echo "$SERVER_HEADER" | grep -qiE "nginx/[0-9]"; then
    echo "  [FAIL] Server header exposes nginx version number"
    exit $FAIL
fi

echo "  [PASS] Server header does not expose version number"

###############################################################################
# PoC Test: Check error pages for version info
###############################################################################
echo ""
echo "[PoC Test] Checking error pages for version disclosure..."

ERROR_PAGE=$(curl -s http://127.0.0.1/nonexistent_page_xyz_12345 2>/dev/null)

if echo "$ERROR_PAGE" | grep -qiE "nginx/[0-9]"; then
    echo "  [FAIL] Error page exposes nginx version"
    exit $FAIL
fi

echo "  [PASS] Error pages do not expose version information"

###############################################################################
# Regression Test: Nginx must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking nginx is running..."

if ! pgrep -x nginx >/dev/null 2>&1; then
    echo "  [FAIL] nginx process is not running"
    exit $FAIL
fi
echo "  [PASS] nginx process is running"

###############################################################################
# Regression Test: Nginx must serve pages
###############################################################################
echo ""
echo "[Regression Test] Checking nginx serves content..."

HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
echo "  HTTP response code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Nginx is not serving pages (HTTP $HTTP_CODE)"
    exit $FAIL
fi

CONTENT=$(curl -s http://127.0.0.1/ 2>/dev/null)
if ! echo "$CONTENT" | grep -q "SysRepair Test Page"; then
    echo "  [FAIL] Nginx served unexpected content"
    exit $FAIL
fi
echo "  [PASS] Nginx serves pages correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# SCENARIO 10: Nginx autoindex on (directory listing)
# =============================================================================
files["scenario-10/Dockerfile"] = r"""# Targets Ubuntu 25.10 (Quantal Quetzal)
FROM ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install nginx
RUN apt-get update && \
    apt-get install -y nginx curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create test content
RUN echo "<html><body><h1>Main Page</h1></body></html>" > /var/www/html/index.html

# Create a directory with files but no index (for directory listing test)
RUN mkdir -p /var/www/html/data && \
    echo "confidential report" > /var/www/html/data/report.txt && \
    echo "internal credentials" > /var/www/html/data/credentials.conf && \
    echo "database export" > /var/www/html/data/dump.sql

# Configure nginx with autoindex on (VULNERABLE)
RUN rm -f /etc/nginx/sites-enabled/default && \
    cat > /etc/nginx/sites-enabled/default << 'NGINXCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.html;
    server_name _;

    location / {
        try_files $uri $uri/ =404;
        autoindex on;
    }
}
NGINXCONF

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
"""

files["scenario-10/threat.md"] = """# Scenario 10: Nginx Autoindex On (Directory Listing)

## Vulnerability

Nginx is configured with `autoindex on`, which enables automatic directory
listings when no index file is present in a directory. This allows attackers
to browse the contents of directories, potentially discovering sensitive
files such as configuration files, database dumps, credentials, and internal
documents.

## CWE Classification

**CWE-548: Exposure of Information Through Directory Listing**

When autoindex is enabled, the web server automatically generates an HTML
page listing all files in a directory when no index file exists. This can
expose sensitive files, internal application structure, backup files, and
temporary files to unauthorized users.

## Affected Configuration

- **File**: `/etc/nginx/sites-enabled/default` (or equivalent site config)
- **Setting**: `autoindex on;` in the `location` block
- **Service**: Nginx
- **Exposed Directory**: `/var/www/html/data/`

## Expected Remediation

- Set `autoindex off;` or remove the `autoindex on;` directive
- Reload or restart nginx
- Nginx must still serve static files by direct URL and the main page

## References

- Team docs nginx hardening checklists
- CIS Benchmark for Nginx - Ensure autoindex is disabled
"""

files["scenario-10/verify.sh"] = r"""#!/usr/bin/env bash
###############################################################################
# Scenario 10 - Verification Script
# Nginx Autoindex On (CWE-548)
#
# PoC Test:        Verify directory listing is disabled
# Regression Test: Verify nginx serves static files and main page
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

echo "========================================"
echo " Scenario 10: Nginx Directory Listing"
echo "========================================"

# Wait for nginx to start
sleep 2

###############################################################################
# PoC Test: Check if directory listing is visible
###############################################################################
echo ""
echo "[PoC Test] Checking for directory listing at /data/..."

DIR_RESPONSE=$(curl -s http://127.0.0.1/data/ 2>/dev/null)
HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/data/ 2>/dev/null)
echo "  HTTP response code for /data/: $HTTP_CODE"

# Check for nginx autoindex markers
if echo "$DIR_RESPONSE" | grep -qi "Index of\|<a href=.*report.txt\|<a href=.*credentials.conf"; then
    echo "  [FAIL] Directory listing is visible"
    exit $FAIL
fi

# If we get a 200 and it shows file names, it's still listing
if [ "$HTTP_CODE" = "200" ] && echo "$DIR_RESPONSE" | grep -qi "report.txt\|credentials.conf\|dump.sql"; then
    echo "  [FAIL] Directory listing shows file names"
    exit $FAIL
fi

echo "  [PASS] Directory listing is not visible (HTTP $HTTP_CODE)"

###############################################################################
# Regression Test: Nginx must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking nginx is running..."

if ! pgrep -x nginx >/dev/null 2>&1; then
    echo "  [FAIL] nginx process is not running"
    exit $FAIL
fi
echo "  [PASS] nginx process is running"

###############################################################################
# Regression Test: Main page must still be served
###############################################################################
echo ""
echo "[Regression Test] Checking main page is served..."

HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Main page not served (HTTP $HTTP_CODE)"
    exit $FAIL
fi

CONTENT=$(curl -s http://127.0.0.1/ 2>/dev/null)
if ! echo "$CONTENT" | grep -q "Main Page"; then
    echo "  [FAIL] Main page has unexpected content"
    exit $FAIL
fi
echo "  [PASS] Main page served correctly"

###############################################################################
# Regression Test: Direct file access must still work
###############################################################################
echo ""
echo "[Regression Test] Checking direct file access works..."

CONTENT=$(curl -s http://127.0.0.1/data/report.txt 2>/dev/null)
HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1/data/report.txt 2>/dev/null)

if [ "$HTTP_CODE" != "200" ]; then
    echo "  [FAIL] Direct file access failed (HTTP $HTTP_CODE)"
    exit $FAIL
fi

if ! echo "$CONTENT" | grep -q "confidential report"; then
    echo "  [FAIL] File content is incorrect"
    exit $FAIL
fi
echo "  [PASS] Direct file access works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
"""

# =============================================================================
# Write all files
# =============================================================================
written = 0
for relpath, content in files.items():
    fullpath = os.path.join(BASE, relpath)
    os.makedirs(os.path.dirname(fullpath), exist_ok=True)
    with open(fullpath, "w") as f:
        f.write(content.lstrip("\n"))
    # Make verify.sh executable
    if relpath.endswith("verify.sh"):
        os.chmod(fullpath, 0o755)
    written += 1
    print(f"  Written: {relpath}")

print(f"\nTotal files written: {written}")
