# Jenkins CLI Arbitrary File Read (CVE-2024-23897)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2024-23897
- CWE-22: Path Traversal (via args4j `@file` expansion)

## Description
Jenkins uses the `args4j` command-line argument parser, which by default
expands any argument beginning with `@` by reading the referenced file and
splitting its content as additional arguments. The Jenkins CLI never
disabled this behavior, so any CLI command reachable to a user (including
anonymous, if the job is discoverable) can be made to read arbitrary files
from the controller filesystem:

```
java -jar jenkins-cli.jar -s http://target:8080 help "@/etc/passwd"
```

Reading `/var/jenkins_home/secrets/master.key` and related secret files
permits offline decryption of stored credentials, which can then be used
to trigger RCE through a configured SSH/agent key or pipeline script.

## Affected Service
- **Service:** Jenkins LTS
- **Port:** 8080/TCP
- **Vulnerable versions:** LTS ≤ 2.426.2, weekly ≤ 2.441
- **Binary:** `/usr/share/jenkins/jenkins.war`

## Remediation Steps
1. Upgrade Jenkins to **LTS 2.426.3** or **weekly 2.442** or later. The
   fix disables args4j's `@`-expansion at the CLI entry point.
2. As a temporary mitigation, remove anonymous access (remove the
   `anonymous` grants from `init.groovy`) and block the `/cli` endpoint
   at a reverse proxy.
3. Verify the Jenkins web UI still responds on port 8080 after upgrade.
