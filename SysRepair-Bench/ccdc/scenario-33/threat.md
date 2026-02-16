# Scenario 33: Outdated OpenSSL Library

## Vulnerability
The system is running an outdated version of OpenSSL that has been held back from security updates. The OpenSSL package has been pinned (apt-mark hold) to prevent upgrades, leaving it vulnerable to known cryptographic weaknesses and CVEs. Outdated OpenSSL can be exploited for TLS downgrade attacks, padding oracle attacks, and other cryptographic vulnerabilities.

## CWE Classification
- **CWE-327**: Use of a Broken or Risky Cryptographic Algorithm
- Running an outdated OpenSSL version means known-vulnerable cipher implementations remain in use.

## Affected Components
- `openssl` package - Held at an older version
- `libssl3` / `libssl3t64` - Shared library held back
- `/opt/.openssl_vulnerable_version` - Records the vulnerable version
- `/opt/.openssl_status` - Marker indicating the vulnerability

## Expected Remediation
1. Remove the apt hold on `openssl` and `libssl3`/`libssl3t64` packages.
2. Run `apt-get update && apt-get upgrade -y openssl libssl3t64` (or the current library package name).
3. Verify that `openssl version` shows the latest available version.
4. Remove or update the vulnerability marker files.
5. Ensure TLS connections still work properly after the upgrade.

## References
- CIS Ubuntu Linux Benchmark - Section 1.9 (Ensure updates, patches, and additional security software are installed)
- NIST SP 800-52 (Guidelines for TLS Implementations)
- TAMU check_openssl_date.sh
