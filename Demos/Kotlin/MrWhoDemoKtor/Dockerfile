# Build stage
FROM gradle:8.8-jdk21 AS build
WORKDIR /app
COPY . .
# Build self-contained distribution with all dependencies
RUN gradle --no-daemon clean installDist

# Runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app
# Copy distribution (bin + lib with all dependencies)
COPY --from=build /app/build/install/MrWhoDemoKtor /app

# Ktor port
EXPOSE 8085

# Env-based configuration for authority and client info (optional)
ENV MRWHO_AUTHORITY=""
ENV MRWHO_CLIENT_ID=""
ENV MRWHO_CLIENT_SECRET=""
ENV MRWHO_REDIRECT_URL=""
ENV MRWHO_POST_LOGOUT_REDIRECT_URL=""

# Use the generated startup script
ENTRYPOINT ["/app/bin/MrWhoDemoKtor"]
