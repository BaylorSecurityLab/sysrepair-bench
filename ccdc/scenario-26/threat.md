# Threat: Hacking Tools Installed on System

## Vulnerability
Multiple offensive security / hacking tools are installed on the system that have no
legitimate purpose on a production server:

- **nmap**: Network scanner used for reconnaissance and port scanning
- **ncat** (netcat): Network utility that can create reverse shells and backdoors
- **hydra**: Password brute-force tool for various network protocols
- **john** (John the Ripper): Password hash cracking tool
- **nikto**: Web server vulnerability scanner

These tools can be used by an attacker who has gained initial access to escalate their
attack, perform lateral movement, crack credentials, and scan for additional vulnerabilities.
Their presence also indicates poor system hygiene and may violate compliance requirements.

## CWE Classification
- **CWE-1104**: Use of Unmaintained Third Party Components
- These are unauthorized third-party tools that should not be present on production systems.

## Affected Packages
The following packages should be removed:
- `nmap`
- `ncat`
- `hydra`
- `john`
- `nikto`

## Expected Remediation
1. Remove all hacking tools: `apt-get purge -y nmap ncat hydra john nikto`
2. Run `apt-get autoremove -y` to clean up dependencies
3. Ensure legitimate system tools (curl, wget, ssh, ping, ip) remain functional

## Source
- TAMU bad_packages.sh (massive removal list of offensive tools)
