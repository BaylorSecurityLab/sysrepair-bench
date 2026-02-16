# Scenario 28: rsh/rlogin Services Enabled

## Vulnerability
The legacy rsh (remote shell) and rlogin services are enabled. These services use `.rhosts` trust-based authentication with no encryption, allowing password-less access and cleartext transmission of all data.

## CWE Classification
**CWE-319**: Cleartext Transmission of Sensitive Information

## Affected Service
rsh-server (in.rshd, in.rlogind via xinetd)

## Issue
rsh and rlogin are insecure legacy protocols that should have been replaced by SSH decades ago. The `.rhosts` file with `+ +` grants access from any host as any user.

## Expected Remediation
1. Stop and disable rsh/rlogin services
2. Remove rsh-server and rsh-client packages
3. Remove `.rhosts` files from all home directories
4. Ensure SSH is available as a replacement

## Impact
All communications are unencrypted. The `.rhosts` trust mechanism allows any host to connect without authentication, providing trivial unauthorized access.

## Source
Team internal checklists, TAMU CCDC linuxmonkeys bad_packages.sh
