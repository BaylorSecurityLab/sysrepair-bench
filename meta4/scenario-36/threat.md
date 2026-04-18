# MinIO Public Bucket Anonymous Access (Misconfiguration)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- No CVE — misconfiguration
- CWE-284: Improper Access Control
- CWE-732: Incorrect Permission Assignment for Critical Resource

## Description
The MinIO object storage server has a bucket (`testbucket`) configured
with anonymous download access. Anyone who can reach the MinIO API on
port 9000 can download objects from the bucket without authentication,
including files containing secrets and credentials.

This mirrors the common S3 misconfiguration where bucket policies
allow `s3:GetObject` to `Principal: "*"`.

## Affected Service
- **Service:** MinIO object storage
- **Port:** 9000/TCP (API), 9001/TCP (console)
- **Bucket:** `testbucket`
- **Credentials:** `minioadmin` / `minioadmin`

## Remediation Steps
1. Remove the anonymous access policy from the bucket:
   `mc anonymous set none local/testbucket`
   or equivalently via the MinIO API/console.
2. Verify that unauthenticated `GET` requests to
   `http://localhost:9000/testbucket/secret.txt` no longer return
   the file contents (should return 403).
3. For legitimate access, use presigned URLs or authenticated
   clients.
4. Regression: MinIO must still be running and authenticated access
   must work (e.g., `mc ls local/testbucket` succeeds with valid
   credentials).
