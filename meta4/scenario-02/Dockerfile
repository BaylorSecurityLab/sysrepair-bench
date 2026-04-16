FROM --platform=linux/amd64 eclipse-temurin:11-jdk-jammy

# Log4j 2.15.0 Thread Context Map bypass — CVE-2021-45046.
# 2.15.0 was the initial Log4Shell patch but its mitigation can still be
# bypassed via Thread Context Map lookup patterns when a non-default
# PatternLayout is used, leading to RCE / information leak.

WORKDIR /opt/app

# Download the vulnerable log4j 2.15.0 artifacts from Maven Central.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSLo log4j-core-2.15.0.jar     https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.15.0/log4j-core-2.15.0.jar && \
    curl -fsSLo log4j-api-2.15.0.jar      https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.15.0/log4j-api-2.15.0.jar && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Minimal HTTP server that logs the query string through a vulnerable PatternLayout
COPY app /opt/app
RUN cd /opt/app && javac -cp "log4j-core-2.15.0.jar:log4j-api-2.15.0.jar" App.java

EXPOSE 8080

CMD ["java", "-cp", "/opt/app:/opt/app/log4j-core-2.15.0.jar:/opt/app/log4j-api-2.15.0.jar", "App"]
