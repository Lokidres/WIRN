# Multi-stage build for minimal image size

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o wirn .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user (though we'll need to run as root for /proc access)
RUN addgroup -S wirn && adduser -S wirn -G wirn

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/wirn .

# Set permissions
RUN chmod +x wirn

# Default command
ENTRYPOINT ["./wirn"]

# Default flags
CMD ["-proc", "-interval", "1000"]

# Metadata
LABEL maintainer="yourname@example.com"
LABEL version="2.0.0"
LABEL description="WIRN - Enhanced Process Monitor"

# Note: Container must be run with --privileged and --pid=host to access host processes
# Example: docker run --privileged --pid=host wirn:latest
