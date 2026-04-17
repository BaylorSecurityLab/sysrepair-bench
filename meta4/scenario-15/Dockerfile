FROM --platform=linux/amd64 jenkins/jenkins:2.441

# Jenkins LTS 2.441 CLI `@`-expansion arbitrary file read → RCE
# (CVE-2024-23897). Jenkins uses the args4j library which treats an
# argument beginning with `@` as "read this file as additional args".
# Any anonymous-permitted CLI command can be used to exfiltrate files
# such as /var/jenkins_home/secrets/master.key, leading to credential
# decryption and remote code execution.

USER root

# Disable the setup wizard and grant anonymous "Overall/Read" so the CLI
# is reachable without credentials — the documented vulnerable posture.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# Minimal groovy init hook: give anonymous Overall/Read + Job/Read.
RUN mkdir -p /usr/share/jenkins/ref/init.groovy.d
COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/init.groovy

USER jenkins
EXPOSE 8080 50000
