# ============================================================================
# Kotlin Spring Boot Demo Client - Dockerfile (for MrWho demos)
# ============================================================================

# Build stage
FROM gradle:8.11-jdk21 AS build
WORKDIR /home/gradle/project

COPY MrWho/demos/kotlin-spring-client/ ./
RUN gradle --no-daemon bootJar

# Runtime stage
FROM eclipse-temurin:21-jdk-jammy
WORKDIR /app

# Install openssl for extracting the demo cert from PFX
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# Import the MrWho demo TLS cert into the JVM truststore
# (MrWhoOidc uses the same aspnetapp.pfx for HTTPS in demos)
COPY MrWhoOidc/certs/aspnetapp.pfx /tmp/aspnetapp.pfx
RUN set -eux; \
  openssl pkcs12 -legacy -in /tmp/aspnetapp.pfx -clcerts -nokeys -passin pass:changeit -out /tmp/aspnetapp.crt; \
  keytool -importcert -noprompt -alias mrwho-demo -file /tmp/aspnetapp.crt -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit; \
  rm -f /tmp/aspnetapp.pfx /tmp/aspnetapp.crt

COPY --from=build /home/gradle/project/build/libs/*.jar /app/app.jar

EXPOSE 5090

ENV JAVA_OPTS=""
ENTRYPOINT ["/bin/sh", "-lc", "java $JAVA_OPTS -jar /app/app.jar"]
