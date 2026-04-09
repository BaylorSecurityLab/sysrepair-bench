FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y default-jdk tomcat9 tomcat9-admin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure Tomcat with WEAK credentials (VULNERABLE)
RUN printf '<?xml version="1.0" encoding="UTF-8"?>\n\
<tomcat-users>\n\
  <role rolename="manager-gui"/>\n\
  <role rolename="admin-gui"/>\n\
  <user username="admin" password="admin" roles="manager-gui,admin-gui"/>\n\
  <user username="tomcat" password="tomcat" roles="manager-gui"/>\n\
</tomcat-users>' > /var/lib/tomcat9/conf/tomcat-users.xml

# Remove IP restriction on manager (VULNERABLE)
RUN mkdir -p /usr/share/tomcat9-admin/manager/META-INF && \
    echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<Context antiResourceLocking="false" privileged="true">\n\
</Context>' > /usr/share/tomcat9-admin/manager/META-INF/context.xml

EXPOSE 8080

COPY verify.sh /verify.sh
CMD ["catalina.sh", "run"]
