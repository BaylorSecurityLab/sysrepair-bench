# UnrealIRCd 3.2.8.1 Backdoor (Remote Code Execution)

## Severity
**High** -- CVSS 7.5

## CVE
CVE-2010-2075

## Description
Between November 2009 and June 2010, the official UnrealIRCd download mirrors distributed a compromised version of UnrealIRCd 3.2.8.1. The backdoor allows remote attackers to execute arbitrary commands on the server by sending a string beginning with `AB;` followed by the command. This is a supply-chain attack where the source code was trojaned before distribution.

Any attacker with network access to the IRC port (typically 6667) can achieve full remote code execution without authentication.

This scenario simulates the backdoored UnrealIRCd by running a service on port 6667 that identifies as version 3.2.8.1 and processes `AB;` prefixed commands, replicating the behavior detected by vulnerability scanners.

## Affected Service / Port
- **Service:** UnrealIRCd (IRC daemon)
- **Port:** 6667

## Vulnerable Version
- UnrealIRCd 3.2.8.1 (compromised tarball from official mirrors)

## Remediation Steps
1. Stop the vulnerable UnrealIRCd service.
2. Remove the backdoored installation:
   ```bash
   rm -rf /opt/unrealircd
   ```
3. If IRC is needed, install a clean IRC daemon (e.g., a verified version of UnrealIRCd 4.x+ or an alternative like `ircd-hybrid`):
   ```bash
   apt-get install ircd-hybrid
   ```
4. If IRC is not needed, ensure port 6667 is not listening.
5. Verify no process responds to `AB;` command injection on port 6667.
