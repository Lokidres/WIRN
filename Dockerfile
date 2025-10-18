# WIRN - Advanced Process Spy Tool
# Docker configuration for containerized deployment

FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o wirn main.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S wirn && \
    adduser -u 1001 -S wirn -G wirn

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/wirn .

# Change ownership
RUN chown wirn:wirn /app/wirn

# Switch to non-root user
USER wirn

# Expose port (if needed for web interface)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep wirn || exit 1

# Default command
ENTRYPOINT ["./wirn"]

# Default arguments
CMD ["--stealth", "--log", "--network"]
