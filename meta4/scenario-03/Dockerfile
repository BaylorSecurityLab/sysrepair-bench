FROM --platform=linux/amd64 eclipse-temurin:11-jdk-jammy

# Log4j 2.16.0 recursive-lookup DoS — CVE-2021-45105.
# 2.16 removed JNDI but still evaluated recursive self-referential
# lookups in context values, causing infinite recursion and a StackOverflow.

WORKDIR /opt/app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSLo log4j-core-2.16.0.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.16.0/log4j-core-2.16.0.jar && \
    curl -fsSLo log4j-api-2.16.0.jar  https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.16.0/log4j-api-2.16.0.jar && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY app /opt/app
RUN cd /opt/app && javac -cp "log4j-core-2.16.0.jar:log4j-api-2.16.0.jar" App.java

EXPOSE 8080

CMD ["java", "-cp", "/opt/app:/opt/app/log4j-core-2.16.0.jar:/opt/app/log4j-api-2.16.0.jar", "App"]
