# Scenario 38: Compiler Tools (gcc/make) on Production

## Vulnerability
Development tools including gcc, g++, make, build-essential, cmake, autoconf, and automake are installed on a production server. These tools allow an attacker to compile exploit code, kernel modules, and rootkits directly on the compromised system.

## CWE Classification
**CWE-1104**: Use of Unmaintained Third Party Components

## Affected Service
System-wide (unnecessary packages)

## Issue
Compiler tools on a production server significantly increase the attack surface. An attacker who gains limited access can compile privilege escalation exploits, custom backdoors, and rootkits locally.

## Expected Remediation
Remove all compiler and development tools:
```bash
apt-get remove --purge gcc g++ make build-essential cmake autoconf automake
apt-get autoremove
```

## Impact
An attacker with shell access can download and compile exploit code, kernel modules, rootkits, and custom backdoors directly on the server, making post-exploitation trivial.

## Source
TAMU CCDC linuxmonkeys bad_packages.sh (removes gcc, make, build-essential)
