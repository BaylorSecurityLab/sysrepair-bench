#!/bin/bash
# Launch Jenkins in the background so PID 1 stays `sleep infinity` and the
# service can be restarted (killed + relaunched) without killing the container.
# jenkins.sh copies /usr/share/jenkins/ref (incl. init.groovy.d) into
# JENKINS_HOME and then execs `java -jar /usr/share/jenkins/jenkins.war`.
nohup /usr/local/bin/jenkins.sh >/var/log/jenkins.log 2>&1 &
