# WIRN - Enhanced Process Monitor
# Makefile for build, test, and deployment

# Variables
BINARY_NAME=wirn
VERSION=2.0.0
BUILD_DIR=build
INSTALL_PATH=/usr/local/bin
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"
GOFILES=$(shell find . -type f -name '*.go')

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

# Default target
.DEFAULT_GOAL := help

# Phony targets
.PHONY: all build install clean test lint run deps dev cross-compile help check-root

## all: Build the project
all: deps lint test build

## build: Build the binary
build: $(BUILD_DIR)/$(BINARY_NAME)
	@printf "$(COLOR_GREEN)✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(COLOR_RESET)\n"

$(BUILD_DIR)/$(BINARY_NAME): $(GOFILES)
	@printf "$(COLOR_BLUE)Building $(BINARY_NAME) v$(VERSION)...$(COLOR_RESET)\n"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

## install: Install binary to system (requires root)
install: build check-root
	@printf "$(COLOR_BLUE)Installing $(BINARY_NAME) to $(INSTALL_PATH)...$(COLOR_RESET)\n"
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@printf "$(COLOR_GREEN)✓ Installed successfully$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)Run with: sudo $(BINARY_NAME)$(COLOR_RESET)\n"

## uninstall: Remove binary from system (requires root)
uninstall: check-root
	@printf "$(COLOR_BLUE)Uninstalling $(BINARY_NAME)...$(COLOR_RESET)\n"
	@rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@printf "$(COLOR_GREEN)✓ Uninstalled successfully$(COLOR_RESET)\n"

## deps: Download and install dependencies
deps:
	@printf "$(COLOR_BLUE)Downloading dependencies...$(COLOR_RESET)\n"
	$(GO) mod download
	$(GO) mod tidy
	@printf "$(COLOR_GREEN)✓ Dependencies installed$(COLOR_RESET)\n"

## test: Run tests
test:
	@printf "$(COLOR_BLUE)Running tests...$(COLOR_RESET)\n"
	$(GO) test -v -race -coverprofile=coverage.out ./...
	@printf "$(COLOR_GREEN)✓ Tests passed$(COLOR_RESET)\n"

## test-coverage: Run tests with coverage report
test-coverage: test
	@printf "$(COLOR_BLUE)Generating coverage report...$(COLOR_RESET)\n"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@printf "$(COLOR_GREEN)✓ Coverage report: coverage.html$(COLOR_RESET)\n"

## lint: Run linters
lint:
	@printf "$(COLOR_BLUE)Running linters...$(COLOR_RESET)\n"
	@which golangci-lint > /dev/null || (printf "$(COLOR_YELLOW)Installing golangci-lint...$(COLOR_RESET)\n" && \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...
	@printf "$(COLOR_GREEN)✓ Lint passed$(COLOR_RESET)\n"

## fmt: Format code
fmt:
	@printf "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)\n"
	$(GO) fmt ./...
	@printf "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)\n"

## vet: Run go vet
vet:
	@printf "$(COLOR_BLUE)Running go vet...$(COLOR_RESET)\n"
	$(GO) vet ./...
	@printf "$(COLOR_GREEN)✓ Vet passed$(COLOR_RESET)\n"

## run: Build and run (requires root)
run: build
	@printf "$(COLOR_YELLOW)Starting $(BINARY_NAME)... (Ctrl+C to stop)$(COLOR_RESET)\n"
	sudo $(BUILD_DIR)/$(BINARY_NAME)

## dev: Run in development mode with all monitors enabled
dev: build
	@printf "$(COLOR_YELLOW)Starting $(BINARY_NAME) in dev mode...$(COLOR_RESET)\n"
	sudo $(BUILD_DIR)/$(BINARY_NAME) -proc -file -net -loglevel debug

## clean: Remove build artifacts
clean:
	@printf "$(COLOR_BLUE)Cleaning build artifacts...$(COLOR_RESET)\n"
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@printf "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)\n"

## cross-compile: Build for multiple platforms
cross-compile: deps
	@printf "$(COLOR_BLUE)Cross-compiling for multiple platforms...$(COLOR_RESET)\n"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=linux GOARCH=386 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-386 .
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@printf "$(COLOR_GREEN)✓ Cross-compilation complete$(COLOR_RESET)\n"
	@ls -lh $(BUILD_DIR)

## release: Create release builds with version tagging
release: clean cross-compile
	@printf "$(COLOR_BLUE)Creating release packages...$(COLOR_RESET)\n"
	@mkdir -p $(BUILD_DIR)/release
	@cd $(BUILD_DIR) && \
		tar czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64 && \
		tar czf release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64 && \
		tar czf release/$(BINARY_NAME)-$(VERSION)-linux-386.tar.gz $(BINARY_NAME)-linux-386 && \
		tar czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64 && \
		tar czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	@printf "$(COLOR_GREEN)✓ Release packages created in $(BUILD_DIR)/release/$(COLOR_RESET)\n"

## docker-build: Build Docker image
docker-build:
	@printf "$(COLOR_BLUE)Building Docker image...$(COLOR_RESET)\n"
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
	@printf "$(COLOR_GREEN)✓ Docker image built$(COLOR_RESET)\n"

## check-root: Verify root privileges
check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		printf "$(COLOR_YELLOW)⚠ This command requires root privileges$(COLOR_RESET)\n"; \
		exit 1; \
	fi

## mod-update: Update all dependencies to latest versions
mod-update:
	@printf "$(COLOR_BLUE)Updating dependencies...$(COLOR_RESET)\n"
	$(GO) get -u ./...
	$(GO) mod tidy
	@printf "$(COLOR_GREEN)✓ Dependencies updated$(COLOR_RESET)\n"

## benchmark: Run benchmarks
benchmark:
	@printf "$(COLOR_BLUE)Running benchmarks...$(COLOR_RESET)\n"
	$(GO) test -bench=. -benchmem ./...
	@printf "$(COLOR_GREEN)✓ Benchmarks complete$(COLOR_RESET)\n"

## security: Run security checks
security:
	@printf "$(COLOR_BLUE)Running security checks...$(COLOR_RESET)\n"
	@which gosec > /dev/null || (printf "$(COLOR_YELLOW)Installing gosec...$(COLOR_RESET)\n" && \
		go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec ./...
	@printf "$(COLOR_GREEN)✓ Security checks passed$(COLOR_RESET)\n"

## help: Show this help message
help:
	@printf "$(COLOR_BOLD)WIRN - Enhanced Process Monitor$(COLOR_RESET)\n"
	@printf "$(COLOR_BOLD)Version: $(VERSION)$(COLOR_RESET)\n\n"
	@printf "$(COLOR_BOLD)Available targets:$(COLOR_RESET)\n"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/  /'
	@printf "\n$(COLOR_BOLD)Usage examples:$(COLOR_RESET)\n"
	@printf "  make build          # Build the binary\n"
	@printf "  make install        # Install system-wide (requires sudo)\n"
	@printf "  make run            # Build and run with default options\n"
	@printf "  make dev            # Run with all monitors in debug mode\n"
	@printf "  make test           # Run all tests\n"
	@printf "  make clean          # Clean build artifacts\n"
	@printf "\n$(COLOR_BOLD)Quick start:$(COLOR_RESET)\n"
	@printf "  1. make deps        # Install dependencies\n"
	@printf "  2. make build       # Build the binary\n"
	@printf "  3. sudo make run    # Run the tool\n"
	@printf "\n"
