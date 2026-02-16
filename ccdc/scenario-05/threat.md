# Scenario 05: SSH Password Auth With No Key Restriction

## Vulnerability
The SSH daemon relies solely on password authentication with public key authentication disabled. This makes the system vulnerable to brute-force password attacks and eliminates the strongest form of SSH authentication.

## CWE Classification
**CWE-308**: Use of Single-factor Authentication

## Affected Service
OpenSSH Server (sshd)

## Configuration File
`/etc/ssh/sshd_config`

## Vulnerable Settings
```
PasswordAuthentication yes
PubkeyAuthentication no
```

## Expected Remediation
Enable `PubkeyAuthentication yes` and ideally set `PasswordAuthentication no` (or at minimum ensure both methods are available). Reload the SSH service after changes.

## Impact
Password-only authentication is susceptible to brute-force attacks, credential stuffing, and password reuse attacks. Disabling public key authentication removes the most secure authentication method.

## Source
TAMU CCDC linuxmonkeys ssh.sh, UTSA 2023 SWCCDC script.sh
