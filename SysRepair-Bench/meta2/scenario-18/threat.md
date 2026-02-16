# UnrealIRCd Authentication Spoofing

## Severity
**Medium** -- CVSS 6.8

## CVE
CVE-2016-7144

## Description
UnrealIRCd versions prior to 3.2.10.7 are vulnerable to an authentication spoofing attack. The vulnerability exists in the way UnrealIRCd handles certificate fingerprint verification for server-to-server links and client authentication. An attacker can spoof the authentication of another user or server by exploiting improper validation of SSL/TLS certificate fingerprints, potentially gaining elevated privileges or impersonating trusted servers in an IRC network.

This scenario simulates a vulnerable UnrealIRCd installation by running a service on port 6667 that identifies as version 3.2.10.6, which is below the patched version 3.2.10.7.

## Affected Service / Port
- **Service:** UnrealIRCd (IRC daemon)
- **Port:** 6667

## Vulnerable Version
- UnrealIRCd < 3.2.10.7

## Remediation Steps
1. Upgrade UnrealIRCd to version 3.2.10.7 or later. Since this is a simulated environment, update the version string and handler:
   ```bash
   echo "3.2.10.7" > /opt/unrealircd/VERSION
   ```
2. Update the IRC handler script to report version 3.2.10.7 or higher.
3. Alternatively, remove UnrealIRCd entirely if IRC is not needed:
   ```bash
   rm -rf /opt/unrealircd
   kill $(pgrep -f ircd-sim)
   ```
4. If keeping IRC, consider migrating to UnrealIRCd 4.x or 5.x for long-term support.
5. Restart the IRC service and verify functionality.
