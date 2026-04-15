# Credential Reuse: Payroll DB Passwords Equal Linux User Passwords

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-522: Insufficiently Protected Credentials
- CWE-308: Use of Single-Factor Authentication

## Description
The `payroll_app.php` application stores employee credentials in a MySQL table
(`payroll.users`). By design in the Metasploitable 3 build, the plaintext
passwords in that table are identical to the Linux shell account passwords for
the corresponding system users (e.g., `leia_organa`, `han_solo`, `artoo_detoo`,
`c_three_pio`, `jabba_the_hutt`, `greedo`, `chewbacca`).

An attacker who gains read access to the payroll database — through the
`payroll_app.php` SQL injection vulnerability or direct MySQL access — can
extract the cleartext (or trivially cracked) passwords and immediately escalate
to shell access on the host. The reverse is also true: a user who enumerates
`/etc/shadow` hashes and cracks one gains application-level access as well.

This violates the principle of least privilege and creates a single point of
credential compromise across two unrelated authentication domains.

## Affected Service
- **Service:** payroll_app.php + Linux PAM
- **Port:** 80/TCP (payroll web app)
- **Database:** `payroll.users` (plaintext password column)
- **OS accounts:** `/etc/shadow` (matched hashes)

## Vulnerable Configuration
Example row from `payroll.users`:
```
| username    | password       |
|-------------|----------------|
| leia_organa | help_me_obiwan |
```
The Linux account `leia_organa` has the same password set via `chpasswd` during
provisioning. Reading either credential source yields both.

## Remediation Steps
Sever the link between OS credentials and application credentials. Choose one or
more of the following:

**Option A — Change the OS user passwords (recommended):**
```bash
echo 'leia_organa:NewRandomPassword1!' | chpasswd
echo 'han_solo:NewRandomPassword2!'    | chpasswd
# Repeat for each affected account
```

**Option B — Lock or remove OS accounts (if shell access is not required):**
```bash
usermod -L leia_organa   # lock without deleting
# or
userdel leia_organa      # delete if account is unused
```

**Option C — Rotate application passwords to values different from the OS:**
```bash
mysql -u root payroll -e \
  "UPDATE users SET password=SHA2(CONCAT('new_salt_', username, RAND()), 256);"
```
Note: Option C alone is insufficient if the app stores passwords in plaintext;
also hash them properly with bcrypt or SHA-512+salt.

After remediation the payroll application must still accept the (now different)
application credentials, and OS login with the old (DB-sourced) password must
fail.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-10/Dockerfile -t meta3u-s10 .
docker run -d --name meta3u-s10 -p 8080:80 meta3u-s10
docker exec meta3u-s10 /bin/bash /verify.sh
docker stop meta3u-s10 && docker rm meta3u-s10
```
