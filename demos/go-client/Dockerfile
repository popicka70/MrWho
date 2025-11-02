# ============================================================================
# Go Client Demo - Multi-Stage Dockerfile
# ============================================================================
# Build stage: Compile the Go application
# Runtime stage: Run the application in a minimal Alpine container
# ============================================================================

# ---------------------------------
# Build Stage
# ---------------------------------
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary
# -ldflags="-w -s" to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o go-web-client .

# ---------------------------------
# Runtime Stage
# ---------------------------------
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk --no-cache add ca-certificates wget

# Copy the compiled binary from builder
COPY --from=builder /build/go-web-client .

# Copy configuration files
COPY config.json .

# Expose the application port
EXPOSE 5080

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5080/health || exit 1

# Run the application
ENTRYPOINT ["/app/go-web-client"]
