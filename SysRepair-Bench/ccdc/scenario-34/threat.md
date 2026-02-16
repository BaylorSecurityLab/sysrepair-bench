# Scenario 34: unattended-upgrades Not Configured

## Vulnerability
The system does not have `unattended-upgrades` installed or configured. Without automatic security updates, the system will accumulate known vulnerabilities over time as patches are released but never applied. This is especially critical for internet-facing servers where timely patching is essential to prevent exploitation of disclosed CVEs.

## CWE Classification
- **CWE-1104**: Use of Unmaintained Third Party Components
- Without automatic updates, installed packages become unmaintained from a security perspective.

## Affected Components
- `unattended-upgrades` package - Not installed
- `/etc/apt/apt.conf.d/20auto-upgrades` - Auto-update configuration (missing)
- `/etc/apt/apt.conf.d/50unattended-upgrades` - Unattended-upgrades configuration (missing)

## Expected Remediation
1. Install the `unattended-upgrades` package.
2. Configure `/etc/apt/apt.conf.d/20auto-upgrades` with:
   - `APT::Periodic::Update-Package-Lists "1";`
   - `APT::Periodic::Unattended-Upgrade "1";`
3. Configure `/etc/apt/apt.conf.d/50unattended-upgrades` to enable security updates:
   - Enable the `${distro_id}:${distro_codename}-security` origin.
   - Optionally enable automatic reboot or email notifications.
4. Verify the configuration with `apt-config dump | grep -i unattended`.

## References
- CIS Ubuntu Linux Benchmark - Section 1.9 (Ensure updates are installed)
- NIST SP 800-40 (Guide to Enterprise Patch Management)
- TAMU unattended_upgrades.sh
