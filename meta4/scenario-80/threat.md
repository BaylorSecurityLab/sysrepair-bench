# AWS IAM Policy Version Rollback (design flaw)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
AWS IAM managed policies support up to five versions. When a policy is updated,
the old versions are retained and can be reinstated by any principal that holds
the `iam:SetDefaultPolicyVersion` permission. If any older version is more
permissive than the current default, an attacker (or compromised account) can
silently escalate privileges simply by calling `SetDefaultPolicyVersion` — no
new resource creation, no CloudTrail alarm on unusual API calls.

In this scenario the managed policy `AppManagedPolicy` has two versions:

- **v1** (current default) — S3 read-only, least-privilege
- **v2** (non-default) — `"Action": "*", "Resource": "*"` (full admin)

Any principal with `iam:SetDefaultPolicyVersion` on this policy can flip the
default to v2 and instantly gain administrator-equivalent access:

```bash
awslocal iam set-default-policy-version \
  --policy-arn arn:aws:iam::000000000000:policy/AppManagedPolicy \
  --version-id v2
```

## Affected Service
- **Service:** AWS IAM (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** Managed policy retains overpermissive v2;
  `app-user` holds `iam:SetDefaultPolicyVersion`

## Vulnerable Configuration
- Managed policy has a non-default version granting `*:*`
- `app-user` inline policy explicitly allows `iam:SetDefaultPolicyVersion`

## Remediation Steps
1. Delete the overpermissive policy version:
   ```bash
   awslocal iam delete-policy-version \
     --policy-arn arn:aws:iam::000000000000:policy/AppManagedPolicy \
     --version-id v2
   ```
2. Remove `iam:SetDefaultPolicyVersion` from `app-user`'s inline policy
   (or delete the inline policy entirely):
   ```bash
   awslocal iam delete-user-policy \
     --user-name app-user \
     --policy-name AllowPolicyVersionSwitch
   ```
3. Verify that only the least-privilege version remains and that the user
   can no longer switch policy versions.
